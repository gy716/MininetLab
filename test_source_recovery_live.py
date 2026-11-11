"""Live recovery test using one controller for block, release, and re-block.

Run sudo python3 test_source_recovery_live.py with the lab stopped.
Results are written to results/source_recovery. The test preserves the real
50-second timer and includes low-rate blocked probes during quarantine.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from test_anomaly import module
from evaluate_task4 import block_count, stop

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results/source_recovery"


def run():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo.")
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", 6653)) == 0:
            raise SystemExit("Stop the existing controller first.")
    if subprocess.check_output(["ovs-vsctl", "list-br"], text=True).strip():
        raise SystemExit("Stop the existing Mininet network first.")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    telemetry = OUTPUT / "telemetry.jsonl"
    telemetry.write_text("")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", MININET_ROUTE_PINS="{}",
               MININET_TELEMETRY_FILE=str(telemetry))
    log = open(OUTPUT / "controller.log", "w")
    controller = subprocess.Popen([str(ROOT / "run_controller.sh")], env=env,
                                   stdout=log, stderr=subprocess.STDOUT)
    net = None
    children = []
    result = {"controller_pid": controller.pid, "flood_duration_seconds": 10,
              "required_quiet_seconds": 50}
    try:
        for _ in range(50):
            assert controller.poll() is None, "Controller exited"
            try:
                connection = socket.create_connection(("127.0.0.1", 6653), timeout=0.1)
                connection.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("Controller did not start")
        net = Mininet(topo=module.MeshTopo(), controller=None,
                       switch=partial(OVSSwitch, protocols="OpenFlow13"))
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        net.start()
        assert net.waitConnected(timeout=10)
        result["initial_pingall_loss"] = net.pingAll(timeout="1")
        assert result["initial_pingall_loss"] == 0
        h1, h2, h3, h6 = net.get("h1", "h2", "h3", "h6")
        result["normal_training_ping"] = h2.cmd("ping -c 5 -W 1 10.0.0.3")
        assert " 0% packet loss" in result["normal_training_ping"]
        started = time.monotonic()
        attack = h2.popen(["timeout", "--signal=INT", "10s",
                           "hping3", "--icmp", "--flood", h3.IP()],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(attack)
        while block_count("s2", h2.IP()) is None and time.monotonic() - started < 7:
            time.sleep(0.2)
        assert block_count("s2", h2.IP()) is not None, "Flood not blocked"
        result["block_after_flood_start_seconds"] = time.monotonic() - started
        print("Source blocked after %.2fs" % result["block_after_flood_start_seconds"], flush=True)
        attack.wait(timeout=12)
        stopped = time.monotonic()
        result["flood_process_elapsed_seconds"] = stopped - started
        result["switches_blocking_after_flood"] = [
            switch.name for switch in net.switches if block_count(switch.name, h2.IP()) is not None]
        assert len(result["switches_blocking_after_flood"]) == 6
        probes = {}
        observations = []
        while time.monotonic() - stopped < 70:
            assert controller.poll() is None, "Recovery must use the same running controller"
            elapsed = time.monotonic() - stopped
            counter = block_count("s2", h2.IP())
            observations.append(dict(seconds_after_stop=elapsed, drop_counter=counter))
            if counter is None:
                result["recovered_after_flood_stop_seconds"] = elapsed
                break
            for scheduled in (10, 30, 45):
                if elapsed >= scheduled and str(scheduled) not in probes:
                    reply = h2.cmd("ping -c 1 -W 1 10.0.0.3")
                    probes[str(scheduled)] = reply
                    assert "100% packet loss" in reply
                    print("Still blocked at %.1fs; low-rate probe sent" % elapsed, flush=True)
            if elapsed >= 20 and "legitimate_ping_during_quarantine" not in result:
                reply = h1.cmd("ping -c 3 -W 1 10.0.0.6")
                result["legitimate_ping_during_quarantine"] = reply
                assert " 0% packet loss" in reply
            time.sleep(0.5)
        assert "recovered_after_flood_stop_seconds" in result, "Source did not recover"
        # Polling can shift the observed boundary by around one interval.
        assert 49 <= result["recovered_after_flood_stop_seconds"] <= 56, result
        time.sleep(0.3)
        result["blocked_probes"] = probes
        result["observations"] = observations
        result["remaining_block_rules"] = [
            switch.name for switch in net.switches if block_count(switch.name, h2.IP()) is not None]
        assert result["remaining_block_rules"] == []
        result["recovered_h2_to_h3"] = h2.cmd("ping -c 3 -W 1 10.0.0.3")
        result["recovered_h3_to_h2"] = h3.cmd("ping -c 3 -W 1 10.0.0.2")
        assert " 0% packet loss" in result["recovered_h2_to_h3"]
        assert " 0% packet loss" in result["recovered_h3_to_h2"]
        result["recovered_pingall_loss"] = net.pingAll(timeout="1")
        assert result["recovered_pingall_loss"] == 0
        print("Recovered after %.2fs, bidirectional pings and pingall passed" %
              result["recovered_after_flood_stop_seconds"], flush=True)

        # A fresh flood must still be detected with the preserved normal EMA.
        restart = time.monotonic()
        second = h2.popen(["timeout", "--signal=INT", "5s",
                           "hping3", "--icmp", "--flood", h3.IP()],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(second)
        while block_count("s2", h2.IP()) is None and time.monotonic() - restart < 7:
            time.sleep(0.2)
        assert block_count("s2", h2.IP()) is not None
        result["reblocked_after_new_flood_seconds"] = time.monotonic() - restart
        assert controller.poll() is None
        result["same_controller_throughout"] = True
        result["passed"] = True
        print("Renewed flood blocked after %.2fs; test passed" %
              result["reblocked_after_new_flood_seconds"], flush=True)
    finally:
        for process in children:
            stop(process)
        if net is not None:
            net.stop()
        stop(controller)
        log.close()
        (OUTPUT / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    run()

