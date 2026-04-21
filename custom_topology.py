#!/usr/bin/env python3
"""
custom_topology.py  -  Mininet topology for Packet Logger project
                       (Project 5: SDN Mininet Simulation)

Topology:
           h1 (10.0.0.1)
            |
           s1 -- h3 (10.0.0.3)
            |
           h2 (10.0.0.2)

Usage:
    # Terminal 1 - start POX controller first:
    cd ~/pox && python3 pox.py log.level --DEBUG packet_logger

    # Terminal 2 - then run topology:
    sudo python3 ~/Downloads/custom_topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

class PacketLoggerTopo(Topo):
    """Single switch, 3 hosts with static IPs and MACs."""

    def build(self):
        s1 = self.addSwitch("s1")

        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01",
                          defaultRoute="via 10.0.0.1")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02",
                          defaultRoute="via 10.0.0.2")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03",
                          defaultRoute="via 10.0.0.3")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def run_test_scenarios(net):
    h1, h2, h3 = net.get("h1", "h2", "h3")

    # ------------------------------------------------------------------
    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 1 - ICMP (ping) between all hosts\n")
    info("=" * 60 + "\n")
    net.pingAll()
    # After pingAll, the MAC table is fully learned. Wait for flows to settle.
    time.sleep(2)

    # ------------------------------------------------------------------
    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 2 - TCP throughput using iperf\n")
    info("  h2 acts as server, h1 as client\n")
    info("=" * 60 + "\n")
    h2.cmd("iperf -s &")
    time.sleep(1)
    result = h1.cmd("iperf -c 10.0.0.2 -t 5")
    info(result + "\n")
    h2.cmd("kill %iperf 2>/dev/null")
    time.sleep(1)

    # ------------------------------------------------------------------
    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 3 - UDP traffic h3 -> h1\n")
    info("=" * 60 + "\n")
    h1.cmd("iperf -s -u &")
    time.sleep(1)
    result = h3.cmd("iperf -c 10.0.0.1 -u -t 5")
    info(result + "\n")
    h1.cmd("kill %iperf 2>/dev/null")
    time.sleep(1)

    # ------------------------------------------------------------------
    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 4 - HTTP request (h2 serves, h1 fetches)\n")
    info("=" * 60 + "\n")
    h2.cmd("python3 -m http.server 8080 &")
    time.sleep(1)
    # BUG FIX: use single quotes inside the cmd string, NOT an f-string,
    # so the literal %{http_code} is passed to curl unchanged.
    result = h1.cmd("curl -s -o /dev/null -w '%{http_code}' http://10.0.0.2:8080/")
    info("HTTP response code: " + result + "\n")
    h2.cmd("kill %python3 2>/dev/null")
    time.sleep(1)

    # ------------------------------------------------------------------
    # Show flow table AFTER learning is complete (fixes empty dump issue)
    info("\n" + "=" * 60 + "\n")
    info("FLOW TABLE DUMP - switch s1\n")
    info("=" * 60 + "\n")
    s1 = net.get("s1")
    flows = s1.cmd("ovs-ofctl -O OpenFlow10 dump-flows s1")
    info(flows + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run():
    setLogLevel("info")
    topo = PacketLoggerTopo()

    info("*** Connecting to POX controller on 127.0.0.1:6633\n")
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633),
        autoSetMacs=False,
    )

    net.start()
    info("*** Network started\n")

    # Force OpenFlow 1.0 so POX understands the messages
    info("*** Setting OpenFlow 1.0 on all switches\n")
    for sw in net.switches:
        sw.cmd("ovs-vsctl set bridge %s protocols=OpenFlow10" % sw.name)

    # Give the controller time to connect and install the table-miss rule
    time.sleep(2)

    info("\n*** Running automated test scenarios ...\n")
    run_test_scenarios(net)

    info("\n*** Opening interactive CLI (type 'exit' to quit)\n")
    CLI(net)

    net.stop()
    info("*** Network stopped\n")


if __name__ == "__main__":
    run()
