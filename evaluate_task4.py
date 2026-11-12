"""Run Task 4's three sequential experiments on one controller and network.

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
RESULTS = Path(os.environ.get("MININET_RESULTS_DIR", str(ROOT / "results/task4_iperf")))
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


def run_case(net, telemetry, controller_log_path, stream_start, client, label, attacker_name, target_name, pinned_path):
    folder = RESULTS / ("case_" + label)
    folder.mkdir(parents=True, exist_ok=True)
    source = "10.0.0." + attacker_name[1:]
    target = "10.0.0." + target_name[1:]
    edge = "s%d-s%d" % tuple(pinned_path)
    case_begin = time.monotonic()
    log_offset = controller_log_path.stat().st_size
    children = []
    files = []
    summary = dict(case=label, attack_source=source, attack_target=target,
                   affected_link=edge, pinned_attack_path=pinned_path,
                   load_cost_alpha=4.0, anomaly_cost_beta=20.0,
                   controller_reused=True, duration=DURATION, attack_start=ATTACK_START, attack_end=ATTACK_END)
    try:
        summary["initial_pingall_loss"] = net.pingAll(timeout="1")
        assert summary["initial_pingall_loss"] == 0

        # Use a common monotonic clock for sender, receiver, and controller.
        # Keep the source/destination pair continuously active through all phases.
        start = time.monotonic() + 2
        summary["start_monotonic"] = start
        summary["stream_offset"] = start - stream_start
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
            assert client.poll() is None, "Continuous iperf client stopped unexpectedly"
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
        summary["post_attack_ping_loss"] = net.ping(
            hosts=[host for host in net.hosts if host.name != attacker_name], timeout="1")
        (folder / "observations.json").write_text(json.dumps(observations, indent=2))

        rows = read_jsonl(telemetry)
        active = [row for row in rows if start <= row["time"] <= start + DURATION]
        # Verify the configured equation for every recorded link, not just
        # the attacked edge. This catches stale coefficients in the controller.
        for row in active:
            for link in row["links"].values():
                expected = link["base_cost"] + 4.0 * link["utilization"] + 20.0 * int(link["anomaly"])
                assert abs(link["weight"] - expected) < 1e-6
        penalties = [row for row in active if row["links"][edge]["anomaly"]]
        summary["penalty_start"] = min(row["time"] - start for row in penalties)
        summary["penalty_end"] = max(row["links"][edge]["anomaly_until"] - start for row in penalties)
        paths = []
        for row in observations:
            if row["path"] and (not paths or row["path"] != paths[-1]["path"]):
                paths.append(dict(time=row["time"], path=row["path"]))
        summary["path_changes"] = paths

        assert blocked_at is not None and summary["block_after_attack_seconds"] < 7
        assert summary["capture_exit"] == 124 and summary["capture_packets"] == ""
        assert summary["drops_after"] > summary["drops_before"]
        assert summary["flood_active_during_capture"]
        assert len(summary["switches_blocking_source"]) == 6
        assert summary["post_attack_ping_loss"] == 0
        assert "100% packet loss" in summary["blocked_source_ping"]
        assert paths[0]["path"] == [1, 2, 6] and paths[-1]["path"] == [1, 2, 6]
        if label == "b":
            assert any(row["path"] == [1, 2, 3, 6] for row in paths)
        else:
            assert all(row["path"] == [1, 2, 6] for row in paths)
        # Reuse this controller, its learned baselines, and the same network.
        # Require a fresh unblocked telemetry sample AND removal of all firewall
        # rules before probing the recovered host. A deadline exposes failures.
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            latest = read_jsonl(telemetry)[-1]
            if (time.monotonic() - latest["time"] < 3
                    and not latest["blocked"]
                    and all(block_count(sw.name, source) is None for sw in net.switches)
                    and not any(link["anomaly"] for link in latest["links"].values())
                    and not any(route["switching"] for route in latest["routes"].values())):
                break
            time.sleep(.5)
        else:
            raise AssertionError("Source or routing state did not recover before next case")
        summary["recovery_verified_at"] = time.monotonic() - start
        summary["recovered_pingall_loss"] = net.pingAll(timeout="1")
        assert summary["recovered_pingall_loss"] == 0
        summary["controller_config"] = latest["config"]
        assert latest["config"]["load_alpha"] == 4.0
        assert latest["config"]["anomaly_beta"] == 20.0
        summary["passed"] = True
        print("CASE %s PASSED paths=%s" % (label, paths), flush=True)
    finally:
        for process in children:
            stop(process)
        # Preserve per-case artifacts consumed by plot_task4.py, while keeping
        # the full uninterrupted controller history at the results root.
        case_end = time.monotonic()
        rows = [r for r in read_jsonl(telemetry) if case_begin <= r["time"] <= case_end]
        (folder / "telemetry.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        with open(controller_log_path, "rb") as handle:
            handle.seek(log_offset)
            (folder / "controller.log").write_bytes(handle.read())
        for handle in files:
            handle.close()
        (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def run_evaluation():
    """Own one controller/network for all cases; always clean up on failure."""
    telemetry = RESULTS / "controller_telemetry.jsonl"
    telemetry.write_text("")
    log_path = RESULTS / "controller.log"
    # Pins affect only attack pairs, never the measured h1 -> h6 flow. Pin all
    # three at startup so no controller restart or live configuration is needed.
    pins = {"10.0.0." + src[1:] + ",10.0.0." + dst[1:]: path
            for _, src, dst, path in CASES}
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
        MININET_ROUTE_PINS=json.dumps(pins), MININET_TELEMETRY_FILE=str(telemetry))
    net = None
    warmers = []
    stream_processes = []
    stream_files = []
    with open(log_path, "w") as output:
        controller = subprocess.Popen([str(ROOT / "run_controller.sh")],
            env=environment, stdout=output, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if controller.poll() is not None:
                    raise RuntimeError("Controller startup failed")
                try:
                    with socket.create_connection(("127.0.0.1", 6653), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("Controller did not listen on 6653")
            net = Mininet(topo=module.MeshTopo(), controller=None,
                switch=partial(OVSSwitch, protocols="OpenFlow13"))
            net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
            net.start()
            assert net.waitConnected(timeout=10)
            assert net.pingAll(timeout="1") == 0
            # Warm every source using approximately the measurement workload's
            # 32 pps / 1200-byte packet rate. Echo replies are detector-exempt.
            # Keep calibration outside measured phases, and verify completion
            # from telemetry rather than assuming a fixed sleep was sufficient.
            for index, host in enumerate(net.hosts):
                target = net.hosts[(index + 1) % len(net.hosts)].IP()
                warmers.append(host.popen(["ping", "-i", "0.03125", "-s", "1172",
                    "-w", "20", target], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                rows = read_jsonl(telemetry)
                latest = rows[-1] if rows else {}
                if latest.get("blocked"):
                    raise AssertionError("Normal warmup traffic was blocked")
                if all(latest.get("warmup", {}).get(host.IP(), {}).get("complete")
                       for host in net.hosts):
                    break
                time.sleep(.5)
            else:
                raise AssertionError("Host warmup failed to complete")
            for process in warmers:
                stop(process)
            print("Warmup complete; evaluating all cases on the same controller.", flush=True)
            # One UDP socket/session spans ALL cases and recovery waits. Server
            # interval reports measure received throughput and sequence-number
            # loss; sender offered rate is not substituted for throughput.
            server_log = open(RESULTS / "iperf_server.csv", "w")
            client_log = open(RESULTS / "iperf_client.log", "w")
            stream_files.extend([server_log, client_log])
            server = net["h6"].popen(["stdbuf", "-oL", "iperf", "-s", "-u",
                "-i", "1", "-y", "C"], stdout=server_log, stderr=subprocess.STDOUT)
            stream_processes.append(server)
            time.sleep(1)
            assert server.poll() is None, "iperf server failed"
            stream_start = time.monotonic()
            client = net["h1"].popen(["iperf", "-c", "10.0.0.6", "-u",
                "-b", "10M", "-l", "1470", "-t", "600", "-i", "1"],
                stdout=client_log, stderr=subprocess.STDOUT)
            stream_processes.append(client)
            (RESULTS / "stream.json").write_text(json.dumps({
                "start_monotonic": stream_start, "offered_mbps": 10,
                "datagram_bytes": 1470, "max_seconds": 600}))
            summaries = [run_case(net, telemetry, log_path, stream_start, client, *case)
                         for case in CASES]
            return summaries
        finally:
            for process in reversed(stream_processes):
                stop(process)
            for handle in stream_files:
                handle.close()
            for process in warmers:
                stop(process)
            if net is not None:
                net.stop()
            stop(controller)


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
    summaries = run_evaluation()
    (RESULTS / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    subprocess.run([sys.executable, str(ROOT / "plot_task4_iperf.py"), str(RESULTS)], check=True)
    print("All three Task 4 cases passed; combined iperf plot generated.", flush=True)

