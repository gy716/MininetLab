"""Loop-safe OpenFlow 1.3 controller for the supplied CEG mesh.

The topology file is the source of truth for switch IDs, port numbers,
host attachment ports and link delays. Start Mininet from that same file.
This controller assumes the topology remains fixed while it is running.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4


class MeshController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Poll ingress flow counters once per second. Rates are packets/second.
    # Compare each sample with the PREVIOUS baseline before updating the EMA,
    # otherwise an attack would immediately raise its own detection threshold.
    POLL_SECONDS = 0.5
    EMA_ALPHA = 0.2
    ANOMALY_MULTIPLIER = 5.0
    MIN_THRESHOLD_PPS = 1500.0
    MONITOR_COOKIE = 0x51010001
    BLOCK_COOKIE = 0x51010002
    # Recovery is based on observed blocked-packet rates. A renewed anomaly
    # restarts this interval; ordinary low-rate probes do not extend it.
    SOURCE_RECOVERY_QUIET_SECONDS = 30.0
    RECOVERY_STATS_MAX_AGE = 3.0

    # These coefficients are expressed in the same cost units as delay (ms).
    # The routing load coefficient is separate from EMA_ALPHA, which controls
    # source anomaly detection. A fully utilized link adds 30 cost units.
    LOAD_COST_ALPHA = 4.0
    ANOMALY_COST_BETA = 20.0
    ANOMALY_HOLD_SECONDS = 30.0
    ROUTE_IDLE_SECONDS = 10.0
    ROUTE_COOKIE_PREFIX = 0x5102000000000000
    ROUTE_COOKIE_MASK = 0xffff000000000000
    # Reconsider active pairs once per polling cycle. Both an absolute and a
    # relative improvement are required, then a cooldown limits oscillation.
    REROUTE_MIN_IMPROVEMENT = 2.0
    REROUTE_MIN_FRACTION = 0.10
    REROUTE_COOLDOWN_SECONDS = 5.0
    BARRIER_TIMEOUT_SECONDS = 2.0
    OLD_PATH_DRAIN_SECONDS = 1.0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Import the actual topology definition instead of maintaining another
        # hand-written adjacency list that could drift from the Mininet network.
        path = Path(__file__).resolve().parent / "reference/ceg_mesh_topo.py"
        # Ryu patches Python's select module for asynchronous I/O. Mininet
        # requires the original select.poll, so read its topology in a separate
        # Python process and return only ordinary JSON data to this controller.
        reader = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("lab_topology", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
topo = module.MeshTopo()
print(json.dumps({
    "ids": {s: int(topo.nodeInfo(s)["dpid"], 16) for s in topo.switches()},
    "hosts": {h: topo.nodeInfo(h)["ip"].split("/")[0] for h in topo.hosts()},
    "links": [[a, b, {"delay": info.get("delay", "1ms"), "bw": info.get("bw")}, topo.port(a, b)]
              for a, b, info in topo.links(withInfo=True)]
}))
"""
        structure = json.loads(subprocess.check_output(
            [sys.executable, "-c", reader, str(path)], text=True))
        ids = structure["ids"]
        switches = set(ids)
        self.graph = nx.Graph()
        self.graph.add_nodes_from(ids.values())
        self.ports = {}
        self.host_ports = {dpid: set() for dpid in ids.values()}
        self.host_locations = {}
        self.host_ips = structure["hosts"]
        self.ingress_hosts = {}
        self.datapaths = {}
        self.flow_samples = {}
        self.source_baselines = {}
        self.blocked_sources = set()
        self.source_quarantines = {}
        self.block_requests = {}
        self.stats_parts = {}
        self.port_peers = {}
        self.port_samples = {}
        self.host_attachments = {}
        self.routes = {}
        self.route_sequence = 0
        self.barrier_waiters = {}
        self.switch_errors = {}
        # Optional evaluation hooks. Normal runs have no pinned routes and no
        # telemetry output. Pins constrain only the experiment's attack pair so
        # its traffic actually traverses the link specified in the assignment.
        self.route_pins = {}
        self.telemetry_path = os.environ.get("MININET_TELEMETRY_FILE")

        for left, right, info, ports in structure["links"]:
            left_port, right_port = ports
            if left in switches and right in switches:
                a, b = ids[left], ids[right]
                # TCLink delays in this supplied topology are expressed in ms.
                # Use them as positive edge weights for Dijkstra and the MST.
                delay = info["delay"]
                if not delay.endswith("ms"):
                    raise ValueError("Expected topology link delays in milliseconds")
                base_cost = float(delay[:-2])
                capacity_bps = float(info["bw"]) * 1e6
                if base_cost <= 0 or capacity_bps <= 0:
                    raise ValueError("Mesh links require positive delay and bandwidth")
                # Preserve C0 independently of weight. Updating weight must
                # never compound a previous load or anomaly penalty.
                self.graph.add_edge(a, b, weight=base_cost, base_cost=base_cost,
                                    capacity_bps=capacity_bps, anomaly_until=0.0,
                                    anomaly=False, utilization=0.0, rate_bps=0.0)
                self.ports[a, b] = left_port
                self.ports[b, a] = right_port
                self.port_peers[a, left_port] = b
                self.port_peers[b, right_port] = a
            else:
                # Host ports are the only ports where learning a source MAC
                # is safe. Learning on transit ports could move a host's location
                # when copies of a flooded packet reach other switches.
                switch, port = (left, left_port) if left in switches else (right, right_port)
                self.host_ports[ids[switch]].add(port)
                host = right if left in switches else left
                self.ingress_hosts[ids[switch], port] = self.host_ips[host]
                self.host_attachments[self.host_ips[host]] = (ids[switch], port)

        for pair, path in json.loads(os.environ.get("MININET_ROUTE_PINS", "{}")).items():
            source, destination = pair.split(",")
            if (not path or len(path) != len(set(path))
                    or path[0] != self.host_attachments[source][0]
                    or path[-1] != self.host_attachments[destination][0]
                    or any(not self.graph.has_edge(a, b) for a, b in zip(path, path[1:]))):
                raise ValueError("Invalid evaluation route pin: %s" % pair)
            self.route_pins[source, destination] = path
            self.logger.info("EVALUATION_PIN pair=%s path=%s", pair, path)

        # A minimum spanning tree provides exactly one broadcast path between
        # any two switches. All mesh links remain available for unicast routing.
        # Keep broadcast forwarding stable as load varies. This tree uses the
        # original delay costs, while unicast uses the live graph weights.
        self.tree = nx.minimum_spanning_tree(self.graph, weight="base_cost")
        self.logger.info("Loaded %d switches, %d mesh links, %d host ports",
                         len(self.graph), self.graph.number_of_edges(),
                         sum(map(len, self.host_ports.values())))
        self.logger.info("Broadcast tree edges: %s", sorted(self.tree.edges()))
        # Ryu's cooperative worker keeps polling independent of PacketIn events.
        # Once forwarding rules are installed, traffic normally stays in OVS.
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        datapath = ev.msg.datapath
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        # Remove rules left by an earlier controller connection before installing
        # our table-miss rule. Unknown packets go to the controller in full.
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch()))
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, parser.OFPMatch(), actions)
        # Table 0 performs source filtering and traffic accounting. Table 1
        # retains the existing shortest-path and tree-flooding forwarding rules.
        self.goto_forwarding(datapath, 0, parser.OFPMatch())
        for (switch, port), source in self.ingress_hosts.items():
            if switch != datapath.id:
                continue
            # Echo replies are responses, not evidence that a victim initiated
            # a flood. All other IPv4 traffic between lab hosts is monitored.
            self.goto_forwarding(datapath, 30, parser.OFPMatch(
                in_port=port, eth_type=0x0800, ipv4_src=source,
                ip_proto=1, icmpv4_type=0))
            for destination in self.host_ips.values():
                if destination != source:
                    self.goto_forwarding(datapath, 20, parser.OFPMatch(
                        in_port=port, eth_type=0x0800, ipv4_src=source,
                        ipv4_dst=destination), cookie=self.MONITOR_COOKIE)
        # Restore the firewall after a switch reconnects during this controller
        # run. A controller restart intentionally begins a new lab session.
        for source in self.blocked_sources:
            self.install_block(datapath, source)
        self.logger.info("Switch s%d connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions, table_id=1, cookie=0):
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=table_id, cookie=cookie,
            priority=priority, match=match,
            instructions=instructions))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        ingress = msg.match["in_port"]
        decoded = packet.Packet(msg.data)
        eth = decoded.get_protocol(ethernet.ethernet)
        ip = decoded.get_protocol(ipv4.ipv4)
        # PacketIn messages queued just before a firewall update must not bypass
        # the new drop rule through a controller-generated PacketOut.
        if ip is not None and ip.src in self.blocked_sources:
            return
        if eth is None or dpid not in self.graph:
            return

        # Discovery frames and IPv6 multicast are outside this IPv4 lab.
        # Dropping them also prevents background traffic from obscuring ARP tests.
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        if ingress in self.host_ports[dpid]:
            self.host_locations[eth.src] = (dpid, ingress)

        if ip is not None:
            # All switches on an IPv4 flow use the same cached path snapshot.
            # Computing a fresh next hop independently at every PacketIn could
            # mix old and new costs and create a loop during a load change.
            output = self.route_ipv4(datapath, ingress, ip.src, ip.dst)
            if output is not None:
                datapath.send_msg(parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=ingress, actions=[parser.OFPActionOutput(output)],
                    data=msg.data))
            return

        destination = self.host_locations.get(eth.dst)
        if destination is not None:
            target_switch, target_port = destination
            if dpid == target_switch:
                output = target_port
            else:
                # Positive delay weights make every hop move closer to the
                # destination. Dijkstra can use redundant links outside the tree.
                path = nx.shortest_path(self.tree, dpid, target_switch)
                output = self.ports[dpid, path[1]]
            if output == ingress:
                return
            actions = [parser.OFPActionOutput(output)]
            # One destination-MAC rule handles subsequent packets in the switch.
            # The initial packet is forwarded explicitly below.
            # L2 control traffic follows the stable tree. Include eth_type so
            # an ARP rule cannot accidentally bypass IPv4 dynamic routing.
            self.add_flow(datapath, 10, parser.OFPMatch(
                eth_type=eth.ethertype, eth_dst=eth.dst), actions)
        else:
            # ARP broadcasts and unknown destinations travel only on tree links.
            # Reject copies arriving on non-tree transit links, and never send
            # a flooded packet back to its ingress port.
            tree_ports = {self.ports[dpid, neighbor] for neighbor in self.tree[dpid]}
            allowed = tree_ports | self.host_ports[dpid]
            if ingress not in allowed:
                return
            actions = [parser.OFPActionOutput(port) for port in sorted(allowed - {ingress})]

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ingress, actions=actions, data=msg.data))


    def goto_forwarding(self, datapath, priority, match, cookie=0):
        """Count matching packets in table 0, then continue to table 1."""
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, cookie=cookie, priority=priority,
            match=match, instructions=[parser.OFPInstructionGotoTable(1)]))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        """Track live connections and discard counters from an old connection."""
        dpid = ev.datapath.id
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dpid] = ev.datapath
        elif self.datapaths.get(dpid) is ev.datapath:
            self.datapaths.pop(dpid, None)
        else:
            return
        self.flow_samples = {key: value for key, value in self.flow_samples.items()
                             if key[0] != dpid}
        self.stats_parts = {key: value for key, value in self.stats_parts.items()
                            if key[0] != dpid}
        self.port_samples = {key: value for key, value in self.port_samples.items()
                             if key[0] != dpid}
        for key, route in list(self.routes.items()):
            if dpid in route["path"]:
                self.remove_route(key)
        # A reconnect resets switch counters, so establish a new observation
        # window rather than treating an unavailable switch as a quiet source.
        for quarantine in self.source_quarantines.values():
            quarantine["samples"].pop(dpid, None)
            quarantine["last_anomaly"] = time.monotonic()

    def monitor(self):
        """Poll source counters, route activity, and physical mesh-port load."""
        while True:
            now = time.monotonic()
            for key, request in list(self.block_requests.items()):
                if now - request["sent"] > self.RECOVERY_STATS_MAX_AGE:
                    self.block_requests.pop(key, None)
                    self.stats_parts.pop(key, None)
                    request["event"].set()
            self.recover_ready_sources(now)
            for key, route in list(self.routes.items()):
                if not route.get("switching") and now - route["last_active"] > self.ROUTE_IDLE_SECONDS:
                    self.remove_route(key)
            # Expire anomaly penalties even if the affected link is now idle.
            for a, b in self.graph.edges():
                self.update_link_cost(a, b, now)
            self.reevaluate_routes(now)
            self.write_telemetry(now)
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                if self.source_quarantines and not any(
                        key[0] == datapath.id for key in self.block_requests):
                    self.request_block_stats(datapath)
                datapath.send_msg(parser.OFPFlowStatsRequest(
                    datapath, table_id=0, cookie=self.MONITOR_COOKIE,
                    cookie_mask=0xffffffffffffffff))
                datapath.send_msg(parser.OFPPortStatsRequest(
                    datapath, 0, datapath.ofproto.OFPP_ANY))
                # Forwarding counters include echo replies, so activity on the
                # return path is measured while replies bypass anomaly scoring.
                datapath.send_msg(parser.OFPFlowStatsRequest(
                    datapath, table_id=1, cookie=self.ROUTE_COOKIE_PREFIX,
                    cookie_mask=self.ROUTE_COOKIE_MASK))
            hub.sleep(self.POLL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, ev):
        """Calculate per-flow deltas, then aggregate once per source host.

        Each monitored flow is an IPv4 source/destination pair at the source's
        access port. Inactive flows do not lower the learned baseline. Counter
        resets or switch reconnects start a fresh measurement window.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        if self.datapaths.get(dpid) is not msg.datapath:
            return
        # Large replies can span several OpenFlow messages. Evaluate the source
        # only after receiving every part of this polling response.
        reply_key = (dpid, msg.xid)
        rows = self.stats_parts.setdefault(reply_key, [])
        rows.extend(msg.body)
        if msg.flags & msg.datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        rows = self.stats_parts.pop(reply_key)
        request = self.block_requests.pop(reply_key, None)
        if request is not None:
            self.block_stats_received(msg.datapath, rows, request)
            return
        for flow in rows:
            if flow.cookie & self.ROUTE_COOKIE_MASK == self.ROUTE_COOKIE_PREFIX:
                key = (flow.match.get("ipv4_src"), flow.match.get("ipv4_dst"))
                route = self.routes.get(key)
                if (route is not None and flow.cookie == route["cookie"]
                        and dpid == route["path"][0]):
                    if flow.packet_count > route["last_count"]:
                        route["last_active"] = time.monotonic()
                    route["last_count"] = flow.packet_count
        source_rates = {}
        for flow in rows:
            if flow.cookie != self.MONITOR_COOKIE:
                continue
            source = flow.match.get("ipv4_src")
            destination = flow.match.get("ipv4_dst")
            key = (dpid, flow.match.get("in_port"), source, destination)
            duration = flow.duration_sec + flow.duration_nsec / 1e9
            previous = self.flow_samples.get(key)
            # Switch flow duration is the clock for these counters, so network
            # latency in receiving a stats reply does not distort the interval.
            if previous is None or duration < previous["duration"]:
                count_delta, elapsed = flow.packet_count, duration
                baseline = None
            else:
                count_delta = flow.packet_count - previous["count"]
                elapsed = duration - previous["duration"]
                baseline = previous["ema"]
            self.flow_samples[key] = {
                "count": flow.packet_count, "duration": duration, "ema": baseline}
            if elapsed <= 0 or count_delta <= 0 or source in self.blocked_sources:
                continue
            rate = count_delta / elapsed
            source_rates[source] = source_rates.get(source, 0.0) + rate
            # Keep the individual flow EMA as well as the aggregate source EMA.
            # Samples that cross the source threshold are excluded below.
            self.flow_samples[key]["rate"] = rate

        for source, rate in source_rates.items():
            baseline = self.source_baselines.get(source, 1.0)
            threshold = max(self.MIN_THRESHOLD_PPS,
                            self.ANOMALY_MULTIPLIER * baseline)
            if rate > threshold:
                self.logger.warning(
                    "ANOMALY source=%s rate=%.2f pps baseline=%.2f threshold=%.2f",
                    source, rate, baseline, threshold)
                self.begin_quarantine(source)
                self.mark_anomaly_paths(source, dpid)
                for datapath in list(self.datapaths.values()):
                    self.install_block(datapath, source)
                continue

            # EMA_new = alpha * sample + (1 - alpha) * EMA_old.
            # The first accepted sample initializes the source baseline.
            updated = rate if source not in self.source_baselines else (
                self.EMA_ALPHA * rate + (1 - self.EMA_ALPHA) * baseline)
            self.source_baselines[source] = updated
            for key, sample in self.flow_samples.items():
                if key[0] == dpid and key[2] == source and "rate" in sample:
                    old = sample["ema"]
                    sample["ema"] = sample["rate"] if old is None else (
                        self.EMA_ALPHA * sample["rate"] + (1 - self.EMA_ALPHA) * old)
            self.logger.info("BASELINE source=%s rate=%.2f pps ema=%.2f threshold=%.2f",
                             source, rate, updated, threshold)

    def route_ipv4(self, datapath, ingress, source, destination):
        """Select one live-cost path per IPv4 source/destination pair.

        New pairs use current costs. Active pairs can be migrated by the monitor
        after hysteresis/cooldown checks. Idle pairs are still removed normally.
        """
        key = (source, destination)
        route = self.routes.get(key)
        if route is None:
            source_attachment = self.host_attachments.get(source)
            target_attachment = self.host_attachments.get(destination)
            # Only a packet entering at its configured source host may create a
            # route. A delayed transit packet from an expired path is discarded.
            if source_attachment != (datapath.id, ingress) or target_attachment is None:
                return None
            path = self.route_pins.get(key) or nx.shortest_path(
                self.graph, source_attachment[0], target_attachment[0], weight="weight")
            if any(switch not in self.datapaths for switch in path):
                return None
            route = self.make_route(key, path)
            self.routes[key] = route
            self.install_path(key, route)
            cost = sum(self.graph[a][b]["weight"] for a, b in zip(path, path[1:]))
            self.logger.info("ROUTE source=%s destination=%s path=%s cost=%.3f",
                             source, destination, path, cost)
        expected = route["ports"].get(datapath.id)
        if expected is None or ingress != expected[0]:
            return None
        route["last_active"] = time.monotonic()
        return expected[1]

    def remove_route(self, key):
        """Delete only this cached path's rules, preserving firewall/accounting."""
        route = self.routes.pop(key)
        self.delete_route_rules(route)

    def delete_route_rules(self, route):
        """Delete one cookie generation, including retired path fragments."""
        for switch in route["path"]:
            datapath = self.datapaths.get(switch)
            if datapath is not None:
                parser, ofp = datapath.ofproto_parser, datapath.ofproto
                datapath.send_msg(parser.OFPFlowMod(
                    datapath=datapath, table_id=1, command=ofp.OFPFC_DELETE,
                    cookie=route["cookie"], cookie_mask=0xffffffffffffffff,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch()))

    def make_route(self, key, path):
        """Allocate a distinct cookie generation and ingress/output map."""
        self.route_sequence += 1
        source_attachment = self.host_attachments[key[0]]
        target_attachment = self.host_attachments[key[1]]
        now = time.monotonic()
        route = {"path": list(path), "ports": {}, "last_count": 0,
                 "last_active": now, "last_reroute": now, "switching": False,
                 "cookie": self.ROUTE_COOKIE_PREFIX | self.route_sequence}
        for index, switch in enumerate(path):
            input_port = source_attachment[1] if index == 0 else self.ports[
                switch, path[index - 1]]
            output_port = target_attachment[1] if index == len(path) - 1 else self.ports[
                switch, path[index + 1]]
            route["ports"][switch] = (input_port, output_port)
        return route

    def install_path(self, key, route, wait=False):
        """Install destination-to-source, optionally confirming every switch.

        Rules match the preceding ingress port as well as the IP pair. A rule
        shared with the old path changes only after the new downstream suffix
        is ready. Old-only rules remain for packets already in flight.
        Waiting runs in a worker greenlet so Ryu can process barrier replies.
        """
        for switch in reversed(route["path"]):
            dp = self.datapaths[switch]
            input_port, output_port = route["ports"][switch]
            error_count = self.switch_errors.get(switch, 0)
            self.add_flow(dp, 20, dp.ofproto_parser.OFPMatch(
                in_port=input_port, eth_type=0x0800, ipv4_src=key[0], ipv4_dst=key[1]),
                [dp.ofproto_parser.OFPActionOutput(output_port)], cookie=route["cookie"])
            if wait:
                self.wait_for_barrier(dp)
                if self.switch_errors.get(switch, 0) != error_count:
                    raise RuntimeError("OpenFlow error while installing path")

    def wait_for_barrier(self, datapath):
        request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
        datapath.set_xid(request)
        key = (datapath.id, request.xid)
        event = hub.Event()
        self.barrier_waiters[key] = event
        try:
            datapath.send_msg(request)
            if not event.wait(timeout=self.BARRIER_TIMEOUT_SECONDS):
                raise RuntimeError("Switch s%d barrier timed out" % datapath.id)
        finally:
            self.barrier_waiters.pop(key, None)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        event = self.barrier_waiters.get((ev.msg.datapath.id, ev.msg.xid))
        if event is not None:
            event.set()

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        switch = ev.msg.datapath.id
        self.switch_errors[switch] = self.switch_errors.get(switch, 0) + 1
        self.logger.error("OPENFLOW_ERROR switch=s%d type=%s code=%s",
                          switch, ev.msg.type, ev.msg.code)

    def reevaluate_routes(self, now):
        """Move active, legitimate flows when an alternative is materially cheaper."""
        for key, route in list(self.routes.items()):
            if (route.get("switching") or key in self.route_pins
                    or key[0] in self.blocked_sources or key[1] in self.blocked_sources
                    or now - route["last_reroute"] < self.REROUTE_COOLDOWN_SECONDS):
                continue
            path = nx.shortest_path(self.graph, route["path"][0],
                                    route["path"][-1], weight="weight")
            old_cost = sum(self.graph[a][b]["weight"] for a, b in
                           zip(route["path"], route["path"][1:]))
            new_cost = sum(self.graph[a][b]["weight"] for a, b in zip(path, path[1:]))
            improvement = max(self.REROUTE_MIN_IMPROVEMENT,
                              self.REROUTE_MIN_FRACTION * old_cost)
            if path != route["path"] and old_cost - new_cost >= improvement:
                route["switching"] = True
                hub.spawn(self.switch_route, key, route, path, old_cost, new_cost)

    def switch_route(self, key, old, path, old_cost, new_cost):
        """Make-before-break update with rollback on missing acknowledgements."""
        new = self.make_route(key, path)
        try:
            self.install_path(key, new, wait=True)
            if self.routes.get(key) is not old:
                raise RuntimeError("Route invalidated during update")
            new["last_reroute"] = new["last_active"] = time.monotonic()
            self.routes[key] = new
            self.logger.info(
                "REROUTE time=%.6f source=%s destination=%s old=%s new=%s old_cost=%.3f new_cost=%.3f",
                time.monotonic(), key[0], key[1], old["path"], path, old_cost, new_cost)
            # Preserve old-only rules briefly so packets already on the former
            # route can reach their destination. Cookie-specific deletion cannot
            # remove the new generation even when the two paths overlap.
        except Exception:
            self.logger.exception("REROUTE_FAILED source=%s destination=%s", *key)
            try:
                if self.routes.get(key) is old:
                    self.install_path(key, old, wait=True)
                    old["last_count"] = 0
                    old["last_active"] = old["last_reroute"] = time.monotonic()
            except Exception:
                self.logger.exception("REROUTE_ROLLBACK_FAILED source=%s destination=%s", *key)
                if self.routes.get(key) is old:
                    self.remove_route(key)
            finally:
                # Rollback has restored any overlapping matches to the old
                # cookie before this removes new-only rule fragments.
                self.delete_route_rules(new)
        else:
            hub.sleep(self.OLD_PATH_DRAIN_SECONDS)
            self.delete_route_rules(old)
        finally:
            old["switching"] = False

    def write_telemetry(self, now):
        """Optional one-second JSONL snapshots used by the reproducible trials."""
        if not self.telemetry_path:
            return
        record = {"time": now, "blocked": sorted(self.blocked_sources),
                  "links": {}, "routes": {}, "source_recovery": {}}
        for source, quarantine in self.source_quarantines.items():
            record["source_recovery"][source] = {
                "last_anomaly": quarantine["last_anomaly"],
                "quiet_seconds": max(0, now - quarantine["last_anomaly"]),
                "recovering": quarantine["recovering"]}
        for a, b, edge in self.graph.edges(data=True):
            record["links"]["s%d-s%d" % (min(a, b), max(a, b))] = {
                name: edge[name] for name in ("base_cost", "weight", "rate_bps",
                                              "utilization", "anomaly", "anomaly_until")}
        for key, route in self.routes.items():
            record["routes"][",".join(key)] = {"path": route["path"],
                "cookie": route["cookie"], "switching": route["switching"]}
        with open(self.telemetry_path, "a") as handle:
            handle.write(json.dumps(record) + "\n")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats(self, ev):
        """Measure link traffic from byte-counter deltas, in bits per second.

        Use TX counters at both endpoints to obtain the two traffic directions.
        RX would count the same packets again. The graph is undirected, so use
        the busier direction as its load, consistent with a full-duplex link's
        per-direction capacity. Each port is independent, including multipart
        replies. Missing replies retain the last known rate until a new sample.
        """
        msg = ev.msg
        if self.datapaths.get(msg.datapath.id) is not msg.datapath:
            return
        now = time.monotonic()
        for port in msg.body:
            key = (msg.datapath.id, port.port_no)
            neighbor = self.port_peers.get(key)
            if neighbor is None or port.tx_bytes == 0xffffffffffffffff:
                continue
            duration = port.duration_sec + port.duration_nsec / 1e9
            previous = self.port_samples.get(key)
            rate = 0.0
            if previous is not None:
                elapsed = duration - previous["duration"]
                delta_bytes = port.tx_bytes - previous["bytes"]
                if elapsed > 0 and delta_bytes >= 0:
                    rate = 8.0 * delta_bytes / elapsed
            # The first sample, a reset counter, or a restarted port establishes
            # a fresh reference. No negative rate or lifetime-average estimate.
            self.port_samples[key] = {"bytes": port.tx_bytes, "duration": duration,
                                      "rate": rate}
            self.update_link_cost(msg.datapath.id, neighbor, now)

    def update_link_cost(self, a, b, now):
        """Apply C(t) = C0 + alpha * utilization(t) + beta * anomaly(t)."""
        edge = self.graph[a][b]
        forward = self.port_samples.get((a, self.ports[a, b]), {}).get("rate", 0.0)
        reverse = self.port_samples.get((b, self.ports[b, a]), {}).get("rate", 0.0)
        rate = max(forward, reverse)
        # TCLink bw uses Mbit/s. Cap utilization at 1 to bound the load penalty
        # when counter bursts or shaping overhead briefly exceed that capacity.
        utilization = min(1.0, rate / edge["capacity_bps"])
        anomaly = now < edge["anomaly_until"]
        cost = (edge["base_cost"] + self.LOAD_COST_ALPHA * utilization
                + self.ANOMALY_COST_BETA * int(anomaly))
        if abs(cost - edge["weight"]) >= 0.1 or anomaly != edge["anomaly"]:
            self.logger.info(
                "LINK_COST s%d-s%d base=%.3f rate=%.0f bps utilization=%.4f anomaly=%d cost=%.3f",
                min(a, b), max(a, b), edge["base_cost"], rate, utilization, anomaly, cost)
        edge.update(weight=cost, rate_bps=rate, utilization=utilization, anomaly=anomaly)

    def mark_anomaly_paths(self, source, dpid):
        """Attribute a source anomaly to the paths it used in this stats window.

        Port counters alone cannot identify a source. Combine the source's
        positive ingress-flow deltas with the installed source/destination paths.
        This infers link impact from the installed paths and source counters.
        Keep the binary penalty for 30 seconds after detection so legitimate
        flows can avoid the affected links while the firewall stops the source.
        Repeated detections on an edge extend its expiry instead of stacking beta.
        """
        now = time.monotonic()
        affected = set()
        for key, sample in self.flow_samples.items():
            if key[0] == dpid and key[2] == source and sample.get("rate", 0) > 0:
                route = self.routes.get((source, key[3]))
                if route is not None:
                    affected.update(tuple(sorted((a, b))) for a, b in
                                    zip(route["path"], route["path"][1:]))
        for a, b in sorted(affected):
            edge = self.graph[a][b]
            edge["anomaly_until"] = max(edge["anomaly_until"], now + self.ANOMALY_HOLD_SECONDS)
            self.update_link_cost(a, b, now)
        self.logger.warning("ANOMALY_LINKS source=%s edges=%s hold_seconds=%.1f",
                            source, sorted(affected), self.ANOMALY_HOLD_SECONDS)

    def begin_quarantine(self, source):
        """Start a new recovery generation, preserving the accepted source EMA."""
        self.blocked_sources.add(source)
        self.source_quarantines[source] = {
            "last_anomaly": time.monotonic(), "samples": {}, "recovering": False}

    def request_block_stats(self, datapath):
        """Poll drop rules, which still count traffic while forwarding is blocked.

        Ordinary ingress-accounting rules are bypassed by the higher-priority
        drop rule. Their lack of traffic cannot establish that a flood stopped.
        Retain the actual quarantine objects to reject late replies belonging
        to a previous block/recovery generation. Empty replies are identifiable
        by request XID and can trigger repair of a missing firewall rule.
        """
        parser = datapath.ofproto_parser
        message = parser.OFPFlowStatsRequest(
            datapath, table_id=0, cookie=self.BLOCK_COOKIE,
            cookie_mask=0xffffffffffffffff)
        datapath.set_xid(message)
        request = {"sent": time.monotonic(), "sources": dict(self.source_quarantines),
                   "event": hub.Event(), "complete": False, "present": set()}
        self.block_requests[datapath.id, message.xid] = request
        datapath.send_msg(message)
        return request

    def block_stats_received(self, datapath, rows, request):
        """Classify continued traffic using drop-counter deltas and the normal threshold.

        The busiest switch's source-drop rate avoids double-counting residual
        in-flight packets seen at several switches. After ingress blocking takes
        effect, the source's access switch normally accounts for all attempts.
        Require fresh samples from every topology switch before recovery.
        """
        now = time.monotonic()
        entries = {flow.match.get("ipv4_src"): flow for flow in rows
                   if flow.cookie == self.BLOCK_COOKIE and flow.priority == 100}
        for source, quarantine in request["sources"].items():
            if self.source_quarantines.get(source) is not quarantine:
                continue
            flow = entries.get(source)
            if flow is None or flow.packet_count == 0xffffffffffffffff:
                # Recovery intentionally deletes rules. Otherwise a missing
                # rule is uncertainty requiring repair and a new quiet window.
                if not quarantine["recovering"]:
                    quarantine["samples"].pop(datapath.id, None)
                    quarantine["last_anomaly"] = now
                    self.install_block(datapath, source)
                continue
            duration = flow.duration_sec + flow.duration_nsec / 1e9
            previous = quarantine["samples"].get(datapath.id)
            rate = 0.0
            if (previous is None or previous["datapath"] is not datapath
                    or duration < previous["duration"] or flow.packet_count < previous["count"]):
                quarantine["last_anomaly"] = now
            elif duration > previous["duration"]:
                rate = (flow.packet_count - previous["count"]) / (duration - previous["duration"])
            else:
                # A duplicate/nonadvancing sample cannot confirm a fresh quiet interval.
                continue
            quarantine["samples"][datapath.id] = {
                "count": flow.packet_count, "duration": duration,
                "seen": now, "rate": rate, "datapath": datapath}
            request["present"].add(source)
            threshold = max(self.MIN_THRESHOLD_PPS,
                            self.ANOMALY_MULTIPLIER * self.source_baselines.get(source, 1.0))
            observed_rate = max(sample["rate"] for sample in quarantine["samples"].values())
            if observed_rate > threshold:
                quarantine["last_anomaly"] = now
        request["complete"] = True
        request["event"].set()

    def recovery_ready(self, quarantine, now):
        """Missing telemetry or a disconnected switch pauses automatic release."""
        if now - quarantine["last_anomaly"] < self.SOURCE_RECOVERY_QUIET_SECONDS:
            return False
        for switch in self.graph:
            sample = quarantine["samples"].get(switch)
            if (sample is None or self.datapaths.get(switch) is not sample["datapath"]
                    or now - sample["seen"] > self.RECOVERY_STATS_MAX_AGE):
                return False
        return True

    def recover_ready_sources(self, now):
        for source, quarantine in list(self.source_quarantines.items()):
            if not quarantine["recovering"] and self.recovery_ready(quarantine, now):
                quarantine["recovering"] = True
                hub.spawn(self.recover_source, source, quarantine)

    def delete_source_block(self, datapath, source):
        """Delete only the exact source firewall rule, then acknowledge it."""
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        errors = self.switch_errors.get(datapath.id, 0)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, command=ofp.OFPFC_DELETE_STRICT,
            cookie=self.BLOCK_COOKIE, cookie_mask=0xffffffffffffffff,
            priority=100, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(eth_type=0x0800, ipv4_src=source)))
        self.wait_for_barrier(datapath)
        if self.switch_errors.get(datapath.id, 0) != errors:
            raise RuntimeError("OpenFlow error removing source block")

    def recover_source(self, source, quarantine):
        """Remove downstream drops first and the source's ingress drop last.

        Keep the software blocked-source guard active until all removals are
        acknowledged. Recheck ingress counters just before release. If activity
        resumes or an acknowledgement fails, reinstall drops and keep the host
        quarantined. This worker can wait while the event handler processes
        counter and barrier replies. No controller restart is needed.
        """
        switches = dict(self.datapaths)
        ingress = self.host_attachments[source][0]
        try:
            if not self.recovery_ready(quarantine, time.monotonic()):
                raise RuntimeError("Recovery observations expired")
            for switch, datapath in switches.items():
                if switch != ingress:
                    self.delete_source_block(datapath, source)
            request = self.request_block_stats(switches[ingress])
            request["event"].wait(timeout=self.RECOVERY_STATS_MAX_AGE)
            if (not request["complete"] or source not in request["present"]
                    or time.monotonic() - quarantine["last_anomaly"] < self.SOURCE_RECOVERY_QUIET_SECONDS
                    or self.source_quarantines.get(source) is not quarantine
                    or self.datapaths != switches):
                raise RuntimeError("Source activity or switch state changed during recovery")
            self.delete_source_block(switches[ingress], source)
            # Baselines and accounting snapshots are retained. An attack sample
            # never trains the EMA, and a renewed flood remains detectable.
            self.blocked_sources.remove(source)
            self.source_quarantines.pop(source)
            self.logger.info("SOURCE_RECOVERED source=%s quiet_seconds=%.3f",
                             source, time.monotonic() - quarantine["last_anomaly"])
        except Exception:
            self.logger.exception("SOURCE_RECOVERY_DEFERRED source=%s", source)
            if self.source_quarantines.get(source) is quarantine:
                quarantine["last_anomaly"] = time.monotonic()
                quarantine["samples"].clear()
                for datapath in list(self.datapaths.values()):
                    try:
                        self.install_block(datapath, source)
                        self.wait_for_barrier(datapath)
                    except Exception:
                        self.logger.exception("SOURCE_BLOCK_RESTORE_FAILED source=%s switch=s%d",
                                              source, datapath.id)
        finally:
            quarantine["recovering"] = False

    def install_block(self, datapath, source):
        """Drop this source IP before forwarding, preserving every mesh link.

        An empty action list drops matching packets. Priority 100 overrides
        accounting and echo-reply exceptions. Zero timeouts keep the source
        blocked until explicit recovery removes the rule. Apply on every switch to
        cover packets already in flight and later traffic on alternative paths.
        """
        self.add_flow(datapath, 100,
                      datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=source),
                      [], table_id=0, cookie=self.BLOCK_COOKIE)
        datapath.send_msg(datapath.ofproto_parser.OFPBarrierRequest(datapath))
        self.logger.warning("FIREWALL source=%s switch=s%d action=drop",
                            source, datapath.id)
