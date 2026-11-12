"""Focused tests for source recovery, counter freshness, and safe rule removal."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from mesh_controller import MeshController


class SourceRecoveryTests(unittest.TestCase):
    def setUp(self):
        with patch("mesh_controller.hub.spawn"):
            self.c = MeshController()
        self.sent = []
        for switch in self.c.graph:
            self.c.datapaths[switch] = SimpleNamespace(
                id=switch, ofproto=ofproto_v1_3,
                ofproto_parser=ofproto_v1_3_parser, send_msg=self.sent.append)
        self.source = "10.0.0.2"
        with patch("mesh_controller.time.monotonic", return_value=0):
            self.c.begin_quarantine(self.source)
        self.q = self.c.source_quarantines[self.source]

    def sample(self, switch, now, count, duration=None, rows_missing=False, quarantine=None):
        q = self.q if quarantine is None else quarantine
        duration = now if duration is None else duration
        flow = SimpleNamespace(cookie=self.c.BLOCK_COOKIE, priority=100,
            match={"ipv4_src": self.source}, packet_count=count,
            duration_sec=int(duration), duration_nsec=0)
        request = dict(sources={self.source: q}, event=hub.Event(),
                       complete=False, present=set())
        with patch("mesh_controller.time.monotonic", return_value=now):
            self.c.block_stats_received(self.c.datapaths[switch],
                                       [] if rows_missing else [flow], request)
        return request

    def fresh_quiet_state(self, now=100):
        for switch, dp in self.c.datapaths.items():
            self.q["samples"][switch] = dict(count=1000, duration=now,
                seen=now, rate=0, datapath=dp)
        self.q["last_anomaly"] = now - self.c.SOURCE_RECOVERY_QUIET_SECONDS - 1

    def test_ongoing_flood_resets_clock_but_low_rate_probes_do_not(self):
        for switch in self.c.graph:
            self.sample(switch, 1, 0)
        flood = int(self.c.MIN_THRESHOLD_PPS * 2)
        self.sample(2, 2, flood)
        self.assertEqual(self.q["last_anomaly"], 2)
        # Clear the high-rate sample, then keep sending ordinary 1 pps probes.
        self.sample(2, 3, flood + 1)
        for switch in self.c.graph:
            self.sample(switch, 3, flood + 1 if switch == 2 else 0)
        last_anomaly = self.q["last_anomaly"]
        before = int(last_anomaly + self.c.SOURCE_RECOVERY_QUIET_SECONDS - 1)
        after = before + 3
        for switch in self.c.graph:
            self.sample(switch, before, flood + before - 2 if switch == 2 else 0)
        self.assertEqual(self.q["last_anomaly"], last_anomaly)
        self.assertFalse(self.c.recovery_ready(self.q, before))
        for switch in self.c.graph:
            self.sample(switch, after, flood + after - 2 if switch == 2 else 0)
        self.assertTrue(self.c.recovery_ready(self.q, after))
        self.sample(2, after + 1, 2 * flood + after - 2)
        self.assertEqual(self.q["last_anomaly"], after + 1)
        self.assertFalse(self.c.recovery_ready(self.q, after + 1))

    def test_stale_missing_and_reset_counters_delay_release(self):
        self.fresh_quiet_state()
        self.assertTrue(self.c.recovery_ready(self.q, 100))
        self.assertFalse(self.c.recovery_ready(self.q, 104))
        self.sample(2, 104, 0, rows_missing=True)
        self.assertNotIn(2, self.q["samples"])
        self.assertEqual(self.q["last_anomaly"], 104)
        self.sample(2, 105, 0, duration=1)
        self.assertEqual(self.q["last_anomaly"], 105)
        self.assertFalse(self.c.recovery_ready(self.q, 105))

    def test_old_generation_reply_cannot_update_new_quarantine(self):
        old = self.q
        with patch("mesh_controller.time.monotonic", return_value=20):
            self.c.begin_quarantine(self.source)
        current = self.c.source_quarantines[self.source]
        self.sample(2, 30, 10000, quarantine=old)
        self.assertEqual(current["last_anomaly"], 20)
        self.assertEqual(current["samples"], {})

    def test_release_removes_ingress_last_and_preserves_baseline(self):
        self.fresh_quiet_state()
        self.c.source_baselines[self.source] = 1.5
        self.q["recovering"] = True
        acknowledgements = []
        final_sample = dict(event=SimpleNamespace(wait=lambda **kw: True),
                            complete=True, present={self.source})
        with patch("mesh_controller.time.monotonic", return_value=100), \
                patch.object(self.c, "wait_for_barrier", side_effect=lambda dp: acknowledgements.append(dp.id)), \
                patch.object(self.c, "request_block_stats", return_value=final_sample):
            self.c.recover_source(self.source, self.q)
        self.assertEqual(acknowledgements[-1], 2)
        self.assertEqual(set(acknowledgements), set(self.c.graph))
        self.assertNotIn(self.source, self.c.blocked_sources)
        self.assertNotIn(self.source, self.c.source_quarantines)
        self.assertEqual(self.c.source_baselines[self.source], 1.5)
        self.assertTrue(all(message.command == ofproto_v1_3.OFPFC_DELETE_STRICT
                            and message.priority == 100
                            and message.cookie == self.c.BLOCK_COOKIE for message in self.sent))

    def test_failed_ack_keeps_quarantine_and_restores_rules(self):
        self.fresh_quiet_state()
        self.q["recovering"] = True
        with patch("mesh_controller.time.monotonic", return_value=100), \
                patch.object(self.c.logger, "exception"), \
                patch.object(self.c, "wait_for_barrier", side_effect=[RuntimeError("timeout")] + [None] * 6):
            self.c.recover_source(self.source, self.q)
        self.assertIn(self.source, self.c.blocked_sources)
        self.assertEqual(self.q["last_anomaly"], 100)
        self.assertFalse(self.q["recovering"])
        self.assertEqual(self.q["samples"], {})

    def test_renewed_activity_during_release_cancels_recovery(self):
        self.fresh_quiet_state()
        self.q["recovering"] = True

        def final_sample(dp):
            self.q["last_anomaly"] = 100
            return dict(event=SimpleNamespace(wait=lambda **kw: True),
                        complete=True, present={self.source})
        with patch("mesh_controller.time.monotonic", return_value=100), \
                patch.object(self.c.logger, "exception"), \
                patch.object(self.c, "wait_for_barrier"), \
                patch.object(self.c, "request_block_stats", side_effect=final_sample):
            self.c.recover_source(self.source, self.q)
        self.assertIn(self.source, self.c.blocked_sources)
        self.assertFalse(self.q["recovering"])


if __name__ == "__main__":
    unittest.main()

