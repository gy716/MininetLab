"""Live load-routing check. Requires a fresh controller on port 6653.

Run sudo python3 test_dynamic_routing.py. This test builds its own network.
Echo-reply load exercises link costs separately from source anomaly blocking.
"""
import signal
import subprocess
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from test_anomaly import module


def first_hop(switch, source, destination):
    dump = subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch], text=True)
    return [line for line in dump.splitlines() if
            "priority=20" in line and "table=1" in line
            and "nw_src=" + source in line and "nw_dst=" + destination in line]


def main():
    topo = module.MeshTopo()
    net = Mininet(topo=topo, controller=None,
                  switch=partial(OVSSwitch, protocols="OpenFlow13"))
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    load = None
    try:
        net.start()
        assert net.waitConnected(timeout=10)
        h1, h2, h3 = net.get("h1", "h2", "h3")
        assert " 0% packet loss" in h2.cmd("ping -c 2 -W 2 10.0.0.1")
        # The normal detector intentionally exempts echo replies. These packets
        # still use the IPv4 forwarding path and contribute to link TX counters.
        # A paced, bounded stream keeps enough headroom for the test pings.
        load = h2.popen(["timeout", "--signal=INT", "30s", "hping3", "--icmp",
                         "--icmptype", "0", "--data", "1200", "-i", "u250", h1.IP()],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        during = h1.cmd("ping -c 3 -W 2 10.0.0.3")
        print("Ping during load:", during)
        assert " 0% packet loss" in during
        rows = first_hop("s1", h1.IP(), h3.IP())
        alternative_port = topo.port("s1", "s4")[0]
        print("Loaded route at s1:", rows)
        assert len(rows) == 1, rows
        assert "actions=output:" + str(alternative_port) in rows[0], rows
        load.send_signal(signal.SIGINT)
        load.wait(timeout=3)
        # Let the load counters settle and let this source/destination route
        # age out. The next packet must cause a new live-cost route decision.
        time.sleep(13)
        after = h1.cmd("ping -c 3 -W 2 10.0.0.3")
        print("Ping after load:", after)
        assert " 0% packet loss" in after
        rows = first_hop("s1", h1.IP(), h3.IP())
        original_port = topo.port("s1", "s2")[0]
        print("Recovered route at s1:", rows)
        assert len(rows) == 1 and "actions=output:" + str(original_port) in rows[0], rows
        print("PASS: new route avoided s1-s2 under load and recovered after idle.")
    finally:
        if load is not None and load.poll() is None:
            load.send_signal(signal.SIGINT)
            try:
                load.wait(timeout=3)
            except subprocess.TimeoutExpired:
                load.kill()
                load.wait()
        net.stop()


if __name__ == "__main__":
    main()

