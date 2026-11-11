"""Run Task 4's three isolated experiments with a fresh controller per case.

Run sudo python3 evaluate_task4.py. Raw logs and samples go to results/task4.
The controller's evaluation pin ensures the assigned attack crosses the named
link, especially s5-s6, whose original cost exceeds the s5-s3-s6 alternative.
"""
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from test_anomaly import module

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results/task4"
DURATION = 65
ATTACK_START = 15
ATTACK_END = 27
CASES = [("a", "h2", "h3", [2, 3]),
         ("b", "h2", "h6", [2, 6]),
         ("c", "h5", "h6", [5, 6])]


def read_jsonl(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # A concurrent writer may still be finishing its last record.
    return rows


def dump_flows(switch, table):
    return subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch, "table=" + str(table)],
        text=True)


def block_count(switch, source):
    for line in dump_flows(switch, 0).splitlines():
        if "priority=100" in line and "nw_src=" + source in line and "actions=drop" in line:
            return int(re.search(r"n_packets=(\d+)", line).group(1))
    return None


def stop(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_case(label, attacker_name, target_name, pinned_path):
    folder = RESULTS / ("case_" + label)
    folder.mkdir(parents=True, exist_ok=True)
    source = "10.0.0." + attacker_name[1:]
    target = "10.0.0." + target_name[1:]
    edge = "s%d-s%d" % tuple(pinned_path)
    telemetry = folder / "telemetry.jsonl"
    telemetry.write_text("")
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
        MININET_ROUTE_PINS=json.dumps({source + "," + target: pinned_path}),
        MININET_TELEMETRY_FILE=str(telemetry))
    controller_log = open(folder / "controller.log", "w")
    controller = subprocess.Popen([str(ROOT / "run_controller.sh")], env=environment,
        stdout=controller_log, stderr=subprocess.STDOUT)
    net = None
    children = []
    files = []
    summary = dict(case=label, attack_source=source, attack_target=target,
                   affected_link=edge, pinned_attack_path=pinned_path,
                   duration=DURATION, attack_start=ATTACK_START, attack_end=ATTACK_END)
    try:
        for _ in range(50):
            if controller.poll() is not None:
                raise RuntimeError("Controller startup failed")
            try:
                connection = socket.create_connection(("127.0.0.1", 6653), timeout=0.1)
                connection.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Controller did not listen on 6653")
        net = Mininet(topo=module.MeshTopo(), controller=None,
            switch=partial(OVSSwitch, protocols="OpenFlow13"))
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        net.start()
        assert net.waitConnected(timeout=10)
        summary["initial_pingall_loss"] = net.pingAll(timeout="1")
        assert summary["initial_pingall_loss"] == 0

        # Use a common monotonic clock for sender, receiver, and controller.
        # Keep the source/destination pair continuously active through all phases.
        start = time.monotonic() + 2
        summary["start_monotonic"] = start
        ready = folder / "receiver.ready"
        if ready.exists():
            ready.unlink()
        receiver = net["h6"].popen([sys.executable, str(ROOT / "task4_probe.py"), "receive",
            "--output", str(folder / "received.jsonl"), "--ready", str(ready),
            "--start", str(start), "--duration", str(DURATION)])
        children.append(receiver)
        for _ in range(50):
            if ready.exists():
                break
            time.sleep(0.02)
        assert ready.exists(), "UDP receiver failed to bind"
        sender = net["h1"].popen([sys.executable, str(ROOT / "task4_probe.py"), "send",
            "--output", str(folder / "sent.jsonl"), "--start", str(start),
            "--duration", str(DURATION)])
        children.append(sender)
        ping_file = open(folder / "continuous_ping.log", "w")
        files.append(ping_file)
        ping = net["h1"].popen(["ping", "-D", "-i", "1", "-w", str(DURATION + 2), "10.0.0.6"],
            stdout=ping_file, stderr=subprocess.STDOUT)
        children.append(ping)
        attack = capture = None
        blocked_at = None
        capture_started = None
        before_drop = None
        observations = []
        for tick in range(DURATION + 1):
            time.sleep(max(0, start + tick - time.monotonic()))
            elapsed = time.monotonic() - start
            if tick == ATTACK_START:
                attack_log = open(folder / "attack.log", "w")
                files.append(attack_log)
                attack = net[attacker_name].popen(
                    ["timeout", "--signal=INT", str(ATTACK_END - ATTACK_START) + "s",
                     "hping3", "--icmp", "--flood", target],
                    stdout=attack_log, stderr=subprocess.STDOUT)
                children.append(attack)
                print("CASE %s attack started on %s" % (label, edge), flush=True)
            rows = read_jsonl(telemetry)
            latest = rows[-1] if rows else {}
            route = latest.get("routes", {}).get("10.0.0.1,10.0.0.6", {})
            observations.append(dict(time=elapsed, path=route.get("path"),
                                     blocked=latest.get("blocked", [])))
            if source in latest.get("blocked", []) and blocked_at is None:
                blocked_at = elapsed
                summary["block_after_attack_seconds"] = elapsed - ATTACK_START
                print("CASE %s source blocked after %.2fs" %
                      (label, summary["block_after_attack_seconds"]), flush=True)
            if blocked_at is not None and capture is None and elapsed >= blocked_at + 1:
                before_drop = block_count("s" + attacker_name[1:], source)
                capture = net[target_name].popen(
                    ["timeout", "--signal=INT", "3s", "tcpdump", "-nn", "-l",
                     "-i", target_name + "-eth0", "-c", "1",
                     "icmp and src host " + source + " and icmp[0] = 8"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append(capture)
                capture_started = elapsed
            if capture is not None and capture.poll() is not None and "capture_exit" not in summary:
                captured, errors = capture.communicate()
                summary.update(capture_exit=capture.returncode, capture_packets=captured.strip(),
                    capture_start=capture_started, capture_end=elapsed,
                    drops_before=before_drop,
                    drops_after=block_count("s" + attacker_name[1:], source),
                    flood_active_during_capture=attack.poll() is None)
                (folder / "capture.log").write_text(errors + captured)
                summary["switches_blocking_source"] = [
                    switch.name for switch in net.switches if block_count(switch.name, source) is not None]
            # Check the block shortly after the flood, within the recovery
            # quarantine, rather than assuming that it lasts indefinitely.
            if tick == ATTACK_END + 3:
                summary["blocked_source_ping"] = net[attacker_name].cmd(
                    "ping -c 1 -W 1 " + target)
                summary["blocked_probe_seconds_after_flood"] = time.monotonic() - start - ATTACK_END
            if tick % 5 == 0:
                snapshot = {switch.name: dump_flows(switch.name, 1) for switch in net.switches}
                (folder / ("flows_%02d.json" % tick)).write_text(json.dumps(snapshot, indent=2))
            if tick % 15 == 0:
                print("CASE %s t=%ds path=%s" % (label, tick, route.get("path")), flush=True)
        sender.wait(timeout=5)
        receiver.wait(timeout=5)
        summary["post_attack_ping_loss"] = net.ping(
            hosts=[host for host in net.hosts if host.name != attacker_name], timeout="1")
        (folder / "observations.json").write_text(json.dumps(observations, indent=2))

        rows = read_jsonl(telemetry)
        active = [row for row in rows if start <= row["time"] <= start + DURATION]
        penalties = [row for row in active if row["links"][edge]["anomaly"]]
        summary["penalty_start"] = min(row["time"] - start for row in penalties)
        summary["penalty_end"] = max(row["links"][edge]["anomaly_until"] - start for row in penalties)
        paths = []
        for row in observations:
            if row["path"] and (not paths or row["path"] != paths[-1]["path"]):
                paths.append(dict(time=row["time"], path=row["path"]))
        summary["path_changes"] = paths

        received = read_jsonl(folder / "received.jsonl")
        # Verify connectivity throughout every five-second measurement interval.
        summary["connected_every_five_seconds"] = all(any(
            start + begin <= row["time"] < start + begin + 5 for row in received)
            for begin in range(0, DURATION, 5))
        assert blocked_at is not None and summary["block_after_attack_seconds"] < 7
        assert summary["capture_exit"] == 124 and summary["capture_packets"] == ""
        assert summary["drops_after"] > summary["drops_before"]
        assert summary["flood_active_during_capture"]
        assert len(summary["switches_blocking_source"]) == 6
        assert summary["post_attack_ping_loss"] == 0
        assert "100% packet loss" in summary["blocked_source_ping"]
        assert summary["connected_every_five_seconds"]
        assert paths[0]["path"] == [1, 2, 6] and paths[-1]["path"] == [1, 2, 6]
        if label == "b":
            assert any(row["path"] == [1, 2, 3, 6] for row in paths)
        else:
            assert all(row["path"] == [1, 2, 6] for row in paths)
        summary["passed"] = True
        print("CASE %s PASSED paths=%s" % (label, paths), flush=True)
    finally:
        for process in children:
            stop(process)
        if net is not None:
            net.stop()
        stop(controller)
        controller_log.close()
        for handle in files:
            handle.close()
        (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run this evaluation with sudo.")
    # Avoid taking over an existing controller or an existing Mininet network.
    with socket.socket() as check:
        if check.connect_ex(("127.0.0.1", 6653)) == 0:
            raise SystemExit("Stop the existing lab controller before evaluation.")
    if subprocess.check_output(["ovs-vsctl", "list-br"], text=True).strip():
        raise SystemExit("Stop the existing Mininet network before evaluation.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    summaries = [run_case(*case) for case in CASES]
    (RESULTS / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print("All three Task 4 cases passed.", flush=True)

