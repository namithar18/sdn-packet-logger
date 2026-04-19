#!/usr/bin/env python3
"""
custom_topology.py  –  Mininet topology for Packet Logger project
                       (Project 5: SDN Mininet Simulation)

Topology:
           h1 (10.0.0.1)
            |
           s1 ── h3 (10.0.0.3)
            |
           h2 (10.0.0.2)

Usage:
    sudo python3 custom_topology.py

Make sure the POX controller is already running:
    cd ~/pox && ./pox.py log.level --DEBUG packet_logger
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time


# -------------------------------------------------------------------
# Topology definition
# -------------------------------------------------------------------
class PacketLoggerTopo(Topo):
    """
    Single switch, 3 hosts.  Simple enough to keep flow tables readable,
    complex enough to show all protocol types (ARP, ICMP, TCP, UDP).
    """

    def build(self):
        # Add switch
        s1 = self.addSwitch("s1")

        # Add hosts with static IPs so logs are predictable
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


# -------------------------------------------------------------------
# Test scenarios
# -------------------------------------------------------------------
def run_test_scenarios(net):
    h1, h2, h3 = net.get("h1", "h2", "h3")

    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 1 – ICMP (ping) between all hosts\n")
    info("=" * 60 + "\n")
    net.pingAll()
    time.sleep(1)

    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 2 – TCP throughput using iperf\n")
    info("  h2 acts as server, h1 as client\n")
    info("=" * 60 + "\n")
    # Start iperf server on h2 in background
    h2.cmd("iperf -s &")
    time.sleep(1)
    # Run iperf client on h1 for 5 seconds
    result = h1.cmd("iperf -c 10.0.0.2 -t 5")
    info(result + "\n")
    h2.cmd("kill %iperf")
    time.sleep(1)

    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 3 – UDP traffic h3 → h1\n")
    info("=" * 60 + "\n")
    h1.cmd("iperf -s -u &")
    time.sleep(1)
    result = h3.cmd("iperf -c 10.0.0.1 -u -t 5")
    info(result + "\n")
    h1.cmd("kill %iperf")
    time.sleep(1)

    info("\n" + "=" * 60 + "\n")
    info("TEST SCENARIO 4 – HTTP request (h2 serves, h1 fetches)\n")
    info("=" * 60 + "\n")
    h2.cmd("python3 -m http.server 8080 &")
    time.sleep(1)
    result = h1.cmd("curl -s -o /dev/null -w '%{http_code}' http://10.0.0.2:8080/")
    info(f"HTTP response code: {result}\n")
    h2.cmd("kill %python3")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
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

    # Give the controller a moment to connect
    time.sleep(2)

    info("\n*** Running automated test scenarios ...\n")
    run_test_scenarios(net)

    info("\n*** Opening interactive CLI (type 'exit' to quit)\n")
    CLI(net)

    net.stop()
    info("*** Network stopped\n")


if __name__ == "__main__":
    run()
