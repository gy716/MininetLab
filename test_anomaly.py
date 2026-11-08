#!/usr/bin/env python3
"""Reproducible live test. Run with sudo while a fresh controller is running.

The flood is confined to Mininet hosts and bounded by a 15-second timeout.
Every child process and network interface created here is stopped in finally.
A fresh controller is required because firewall blocks persist for its lifetime.
"""
import importlib.util
import json
from pathlib import Path
import re
import signal
import subprocess
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "lab_topology", str(ROOT / "reference/ceg_mesh_topo.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def drop_counter(switch):
    """Read the actual dataplane firewall entry and its dropped-packet count."""
    dump = subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch, "table=0"],
        text=True)
    entries = [line for line in dump.splitlines()
               if "priority=100" in line and "nw_src=10.0.0.1" in line
               and "actions=drop" in line]
    if not entries:
        return None
    return int(re.search(r"n_packets=(\d+)", entries[0]).group(1))


def run_test():
    setLogLevel("info")
    net = Mininet(topo=module.MeshTopo(), controller=None, link=TCLink,
                  switch=partial(OVSSwitch, protocols="OpenFlow13"))
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    children = []
    results = {}
    try:
        net.start()
        assert net.waitConnected(timeout=10), "Switches did not connect to Ryu"
        results["initial_pingall_loss_percent"] = net.pingAll(timeout="1")
        assert results["initial_pingall_loss_percent"] == 0

        h1, h2, h3, h4 = (net.get(name) for name in ("h1", "h2", "h3", "h4"))
        # Ten ordinary one-second pings establish a low normal-traffic baseline.
        training = h1.cmd("ping -c 10 -i 1 -W 1 10.0.0.2")
        results["normal_ping"] = training
        assert " 0% packet loss" in training
        time.sleep(2)  # Allow the final normal sample to reach the controller.

        # Keep legitimate probes running while h1 floods h2. Use a subprocess
        # rather than shell background jobs so cleanup has an exact process ID.
        legitimate = h3.popen(["ping", "-c", "12", "-i", "1", "-W", "1", h4.IP()],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True)
        children.append(legitimate)
        attack = h1.popen(["timeout", "--signal=INT", "15s", "hping3",
                          "--icmp", "--flood", h2.IP()],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(attack)
        started = time.monotonic()
        while drop_counter("s1") is None and time.monotonic() - started < 7:
            time.sleep(0.2)
        assert drop_counter("s1") is not None, "Source was not blocked within 7 seconds"
        results["block_detected_after_seconds"] = round(time.monotonic() - started, 3)
        # A short drain interval excludes packets sent before the rule arrived.
        time.sleep(1)
        before = drop_counter("s1")
        # Capture at the actual destination. timeout exit 124 means no matching
        # packet reached h2 during the three-second observation window.
        capture = h2.popen(
            ["timeout", "--signal=INT", "3s", "tcpdump", "-nn", "-l",
             "-i", "h2-eth0", "-c", "1",
             "icmp and src host 10.0.0.1 and icmp[0] = 8"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(capture)
        captured, capture_error = capture.communicate(timeout=5)
        after = drop_counter("s1")
        results["destination_capture"] = captured
        results["destination_capture_status"] = capture.returncode
        results["drop_counter_before"] = before
        results["drop_counter_after"] = after
        assert capture.returncode == 124 and not captured.strip(), capture_error
        assert attack.poll() is None, "Flood stopped before blocking was verified"
        assert after > before, "Firewall counter did not increase during the flood"
        results["switches_with_source_block"] = [
            switch.name for switch in net.switches if drop_counter(switch.name) is not None]
        assert len(results["switches_with_source_block"]) == 6

        # Source isolation must not disable the victim or any transit switch.
        # Check every directed pair among the five legitimate hosts while the
        # attack process is still generating traffic at the blocked ingress.
        legitimate_hosts = [host for host in net.hosts if host.name != "h1"]
        results["legitimate_pingall_loss_percent"] = net.ping(
            hosts=legitimate_hosts, timeout="1")
        assert results["legitimate_pingall_loss_percent"] == 0
        assert attack.poll() is None, "Flood expired before legitimate-host testing finished"
        continuous, _ = legitimate.communicate(timeout=15)
        results["legitimate_continuous_ping"] = continuous
        assert " 0% packet loss" in continuous
        # Stop the flood and drain the host's transmit queue before checking
        # that the persistent firewall also blocks ordinary low-rate pings.
        attack.send_signal(signal.SIGINT)
        attack.wait(timeout=3)
        time.sleep(2)
        blocked_ping = h1.cmd("ping -c 3 -W 1 10.0.0.2")
        results["blocked_source_ping"] = blocked_ping
        assert "100% packet loss" in blocked_ping
        assert "No buffer space" not in blocked_ping
        results["passed"] = True
    finally:
        for child in children:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        net.stop()
        (ROOT / "anomaly_test_results.json").write_text(
            json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    run_test()
