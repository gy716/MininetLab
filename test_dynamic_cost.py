"""Deterministic checks for dynamic costs and path selection.

Run with python3 -m unittest -v test_dynamic_cost.py inside the VM.
These checks use real topology/parser objects and simulated switch counters.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from mesh_controller import MeshController


class DynamicCostTests(unittest.TestCase):
    def setUp(self):
        with patch("mesh_controller.hub.spawn"):
            self.controller = MeshController()
        self.sent = []
        for switch in self.controller.graph:
            self.controller.datapaths[switch] = SimpleNamespace(
                id=switch, ofproto=ofproto_v1_3,
                ofproto_parser=ofproto_v1_3_parser, send_msg=self.sent.append)

    def sample(self, switch, neighbor, seconds, tx_bytes):
        controller = self.controller
        port = SimpleNamespace(
            port_no=controller.ports[switch, neighbor], duration_sec=seconds,
            duration_nsec=0, tx_bytes=tx_bytes)
        controller.port_stats(SimpleNamespace(msg=SimpleNamespace(
            datapath=controller.datapaths[switch], body=[port])))

    def test_original_delays_and_full_duplex_load(self):
        c = self.controller
        expected = {(1, 2): 5, (2, 3): 10, (4, 5): 15, (5, 6): 20,
                    (1, 4): 8, (2, 5): 12, (3, 6): 7, (1, 5): 18,
                    (2, 4): 6, (2, 6): 14, (3, 5): 9}
        for (a, b), cost in expected.items():
            self.assertEqual(c.graph[a][b]["weight"], cost)
            self.assertEqual(c.graph[a][b]["capacity_bps"], 40e6)
        for a, b in ((1, 2), (2, 1)):
            self.sample(a, b, 1, 0)
            self.sample(a, b, 2, 2500000)  # 20 Mbit/s in each direction
        self.assertEqual(c.graph[1][2]["weight"], 20)  # 5 + 30 * 0.5
        self.sample(2, 1, 3, 12500000)  # 80 Mbit/s burst, capped at 100%
        self.assertEqual(c.graph[1][2]["weight"], 35)
        # A reset reinitializes both directions instead of producing negatives.
        self.sample(1, 2, 0, 0)
        self.sample(2, 1, 0, 0)
        self.assertEqual(c.graph[1][2]["weight"], 5)

    def test_new_routes_use_costs_and_cached_paths_stay_consistent(self):
        c = self.controller
        self.sample(1, 2, 1, 0)
        self.sample(1, 2, 2, 2500000)
        source, target = "10.0.0.1", "10.0.0.2"
        switch, port = c.host_attachments[source]
        c.route_ipv4(c.datapaths[switch], port, source, target)
        self.assertEqual(c.routes[source, target]["path"], [1, 4, 2])
        # PacketIn follows the committed cached path. The monitor is responsible
        # for explicitly migrating it or removing an idle route.
        self.sample(1, 2, 3, 2500000)
        c.route_ipv4(c.datapaths[switch], port, source, target)
        self.assertEqual(c.routes[source, target]["path"], [1, 4, 2])
        old_cookie = c.routes[source, target]["cookie"]
        c.remove_route((source, target))
        c.route_ipv4(c.datapaths[switch], port, source, target)
        self.assertEqual(c.routes[source, target]["path"], [1, 2])
        self.assertNotEqual(c.routes[source, target]["cookie"], old_cookie)

    def test_anomaly_attribution_and_expiry(self):
        c = self.controller
        source, target = "10.0.0.1", "10.0.0.2"
        switch, port = c.host_attachments[source]
        c.route_ipv4(c.datapaths[switch], port, source, target)
        c.flow_samples[switch, port, source, target] = {"rate": 1000}
        c.blocked_sources.add(source)
        c.mark_anomaly_paths(source, switch)
        self.assertEqual(c.graph[1][2]["weight"], 55)
        self.assertEqual(c.graph[1][4]["weight"], 8)
        expiry = c.graph[1][2]["anomaly_until"]
        c.update_link_cost(1, 2, expiry + 1)
        self.assertEqual(c.graph[1][2]["weight"], 5)
        self.assertIn(source, c.blocked_sources)  # Firewall outlives link penalty.

    def test_active_reroute_waits_downstream_first(self):
        c = self.controller
        source, target = "10.0.0.1", "10.0.0.2"
        switch, port = c.host_attachments[source]
        c.route_ipv4(c.datapaths[switch], port, source, target)
        old = c.routes[source, target]
        # A strong penalty makes the alternative 1-4-2 materially cheaper.
        c.graph[1][2]["weight"] = 55
        with patch("mesh_controller.hub.spawn") as spawn:
            c.reevaluate_routes(old["last_reroute"] + 6)
            self.assertEqual(spawn.call_count, 1)
            args = spawn.call_args[0]
        acknowledged = []
        with patch.object(c, "wait_for_barrier", side_effect=lambda dp: acknowledged.append(dp.id)), \
                patch("mesh_controller.hub.sleep"):
            args[0](*args[1:])
        self.assertEqual(acknowledged, [2, 4, 1])
        self.assertEqual(c.routes[source, target]["path"], [1, 4, 2])
        self.assertNotEqual(c.routes[source, target]["cookie"], old["cookie"])
        # The cooldown prevents an immediate migration back after cost recovery.
        c.graph[1][2]["weight"] = 5
        with patch("mesh_controller.hub.spawn") as spawn:
            c.reevaluate_routes(c.routes[source, target]["last_reroute"] + 1)
            spawn.assert_not_called()

    def test_failed_acknowledgement_restores_previous_path(self):
        c = self.controller
        key = ("10.0.0.1", "10.0.0.2")
        switch, port = c.host_attachments[key[0]]
        c.route_ipv4(c.datapaths[switch], port, *key)
        old = c.routes[key]
        old["switching"] = True
        with patch.object(c, "wait_for_barrier", side_effect=[RuntimeError("timeout"), None, None]), \
                patch.object(c.logger, "exception"):
            c.switch_route(key, old, [1, 4, 2], 55, 14)
        self.assertIs(c.routes[key], old)
        self.assertEqual(old["path"], [1, 2])
        self.assertFalse(old["switching"])


if __name__ == "__main__":
    unittest.main()

