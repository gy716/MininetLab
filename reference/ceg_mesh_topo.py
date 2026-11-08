"""
CEG5101 CA2 Mesh Topology with Link Costs

Topology:
    Hosts:    h1 - h6
    Switches: s1 - s6

The switch-to-switch links form a redundant mesh so that
Dijkstra-based routing can select alternative paths when a
link fails or its dynamic cost increases.

Base Link cost is represented by the TCLink delay.
"""

from mininet.topo import Topo
from mininet.link import TCLink


class MeshTopo(Topo):
    def build(self):

        # =========================================================
        # 1. Create switches
        # =========================================================
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000002')
        s3 = self.addSwitch('s3', dpid='0000000000000003')
        s4 = self.addSwitch('s4', dpid='0000000000000004')
        s5 = self.addSwitch('s5', dpid='0000000000000005')
        s6 = self.addSwitch('s6', dpid='0000000000000006')

        # =========================================================
        # 2. Create hosts
        # =========================================================
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')

        # =========================================================
        # 3. Connect one host to each switch
        # =========================================================
        # Host links use the same bandwidth and delay.
        self.addLink(
            s1, h1, cls=TCLink, bw=40, delay='15ms'
        )
        self.addLink(
            s2, h2, cls=TCLink, bw=40, delay='15ms'
        )
        self.addLink(
            s3, h3, cls=TCLink, bw=40, delay='15ms'
        )
        self.addLink(
            s4, h4, cls=TCLink, bw=40, delay='15ms'
        )
        self.addLink(
            s5, h5, cls=TCLink, bw=40, delay='15ms'
        )
        self.addLink(
            s6, h6, cls=TCLink, bw=40, delay='15ms'
        )

        # =========================================================
        # 4. Switch-to-switch mesh links
        # =========================================================
        self.addLink(
            s1, s2, cls=TCLink, bw=40, delay='5ms'
        )   # Cost: 5

        self.addLink(
            s2, s3, cls=TCLink, bw=40, delay='10ms'
        )   # Cost: 10

        # Bottom row
        self.addLink(
            s4, s5, cls=TCLink, bw=40, delay='15ms'
        )   # Cost: 15

        self.addLink(
            s5, s6, cls=TCLink, bw=40, delay='20ms'
        )   # Cost: 20

        # Vertical links
        self.addLink(
            s1, s4, cls=TCLink, bw=40, delay='8ms'
        )   # Cost: 8

        self.addLink(
            s2, s5, cls=TCLink, bw=40, delay='12ms'
        )   # Cost: 12

        self.addLink(
            s3, s6, cls=TCLink, bw=40, delay='7ms'
        )   # Cost: 7

        # Diagonal / redundant links
        self.addLink(
            s1, s5, cls=TCLink, bw=40, delay='18ms'
        )   # Cost: 18

        self.addLink(
            s2, s4, cls=TCLink, bw=40, delay='6ms'
        )   # Cost: 6

        self.addLink(
            s2, s6, cls=TCLink, bw=40, delay='14ms'
        )   # Cost: 14

        self.addLink(
            s3, s5, cls=TCLink, bw=40, delay='9ms'
        )   # Cost: 9


# =============================================================
# Register the topology
# =============================================================
topos = {
    'meshTopo': (lambda: MeshTopo())
}
