"""Loop-safe OpenFlow 1.3 controller for the supplied CEG mesh.

The topology file is the source of truth for switch IDs, port numbers,
host attachment ports and link delays. Start Mininet from that same file.
This controller assumes the topology remains fixed while it is running.
"""
import json
import subprocess
import sys
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
    POLL_SECONDS = 1.0
    EMA_ALPHA = 0.2
    ANOMALY_MULTIPLIER = 5.0
    MIN_THRESHOLD_PPS = 50.0
    MONITOR_COOKIE = 0x51010001
    BLOCK_COOKIE = 0x51010002

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Import the actual topology definition instead of maintaining another
        # hand-written adjacency list that could drift from the Mininet network.
        path = Path(__file__).resolve().parent.parent / "ceg5101Lab/reference/ceg_mesh_topo.py"
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
    "links": [[a, b, {"delay": info.get("delay", "1ms")}, topo.port(a, b)]
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
        self.stats_parts = {}

        for left, right, info, ports in structure["links"]:
            left_port, right_port = ports
            if left in switches and right in switches:
                a, b = ids[left], ids[right]
                # TCLink delays in this supplied topology are expressed in ms.
                # Use them as positive edge weights for Dijkstra and the MST.
                delay = info["delay"]
                if not delay.endswith("ms"):
                    raise ValueError("Expected topology link delays in milliseconds")
                self.graph.add_edge(a, b, weight=float(delay[:-2]))
                self.ports[a, b] = left_port
                self.ports[b, a] = right_port
            else:
                # Host ports are the only ports where learning a source MAC
                # is safe. Learning on transit ports could move a host's location
                # when copies of a flooded packet reach other switches.
                switch, port = (left, left_port) if left in switches else (right, right_port)
                self.host_ports[ids[switch]].add(port)
                host = right if left in switches else left
                self.ingress_hosts[ids[switch], port] = self.host_ips[host]

        # A minimum spanning tree provides exactly one broadcast path between
        # any two switches. All mesh links remain available for unicast routing.
        self.tree = nx.minimum_spanning_tree(self.graph, weight="weight")
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

        destination = self.host_locations.get(eth.dst)
        if destination is not None:
            target_switch, target_port = destination
            if dpid == target_switch:
                output = target_port
            else:
                # Positive delay weights make every hop move closer to the
                # destination. Dijkstra can use redundant links outside the tree.
                path = nx.shortest_path(self.graph, dpid, target_switch, weight="weight")
                output = self.ports[dpid, path[1]]
            if output == ingress:
                return
            actions = [parser.OFPActionOutput(output)]
            # One destination-MAC rule handles subsequent packets in the switch.
            # The initial packet is forwarded explicitly below.
            self.add_flow(datapath, 10, parser.OFPMatch(eth_dst=eth.dst), actions)
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

    def monitor(self):
        """Request only our ingress accounting flows, never transit counters."""
        while True:
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                datapath.send_msg(parser.OFPFlowStatsRequest(
                    datapath, table_id=0, cookie=self.MONITOR_COOKIE,
                    cookie_mask=0xffffffffffffffff))
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
        # Large replies can span several OpenFlow messages. Evaluate the source
        # only after receiving every part of this polling response.
        reply_key = (dpid, msg.xid)
        rows = self.stats_parts.setdefault(reply_key, [])
        rows.extend(msg.body)
        if msg.flags & msg.datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        rows = self.stats_parts.pop(reply_key)
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
                self.blocked_sources.add(source)
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

    def install_block(self, datapath, source):
        """Drop this source IP before forwarding, preserving every mesh link.

        An empty action list drops matching packets. Priority 100 overrides
        accounting and echo-reply exceptions. Zero timeouts keep the source
        blocked until this controller is restarted. Apply on every switch to
        cover packets already in flight and later traffic on alternative paths.
        """
        self.add_flow(datapath, 100,
                      datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=source),
                      [], table_id=0, cookie=self.BLOCK_COOKIE)
        datapath.send_msg(datapath.ofproto_parser.OFPBarrierRequest(datapath))
        self.logger.warning("FIREWALL source=%s switch=s%d action=drop",
                            source, datapath.id)
