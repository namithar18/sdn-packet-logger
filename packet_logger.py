"""
Packet Logger - SDN Controller using POX
Project 5: Capture and log packets traversing the network using controller events.

Features:
  - Captures packet headers (src/dst MAC, IP, port)
  - Identifies protocol types (TCP, UDP, ICMP, ARP)
  - Maintains timestamped logs (packet_log.txt)
  - Displays packet information in terminal
  - Installs flow rules for known flows (acts as learning switch + logger)
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.packet import ethernet, ipv4, tcp, udp, icmp, arp
import pox.openflow.libopenflow_01 as of
from datetime import datetime
import os

log = core.getLogger()

LOG_FILE = "packet_log.txt"


def log_packet(dpid, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    entry = "[%s] [Switch %s] %s" % (timestamp, dpidToStr(dpid), msg)
    log.info(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


def describe_packet(eth):
    # ARP
    if eth.type == ethernet.ARP_TYPE:
        a = eth.payload
        if not isinstance(a, arp):
            return "ARP (unparsed)"
        op = "REQUEST" if a.opcode == arp.REQUEST else "REPLY"
        return "ARP %s | src_mac=%s dst_mac=%s | src_ip=%s dst_ip=%s" % (
            op, eth.src, eth.dst, a.protosrc, a.protodst)

    # IPv4
    if eth.type == ethernet.IP_TYPE:
        ip_pkt = eth.payload
        if not isinstance(ip_pkt, ipv4):
            return "IPv4 (unparsed)"

        proto_map = {
            ipv4.TCP_PROTOCOL:  "TCP",
            ipv4.UDP_PROTOCOL:  "UDP",
            ipv4.ICMP_PROTOCOL: "ICMP",
        }
        proto_name = proto_map.get(ip_pkt.protocol, "IP_PROTO_%d" % ip_pkt.protocol)
        base = "%s | src_mac=%s dst_mac=%s | src_ip=%s dst_ip=%s | ttl=%s" % (
            proto_name, eth.src, eth.dst, ip_pkt.srcip, ip_pkt.dstip, ip_pkt.ttl)

        if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
            t = ip_pkt.payload
            if not isinstance(t, tcp):
                return base
            flags = []
            if t.SYN: flags.append("SYN")
            if t.ACK: flags.append("ACK")
            if t.FIN: flags.append("FIN")
            if t.RST: flags.append("RST")
            if t.PSH: flags.append("PSH")
            return "%s | src_port=%s dst_port=%s | flags=[%s]" % (
                base, t.srcport, t.dstport, ",".join(flags))

        if ip_pkt.protocol == ipv4.UDP_PROTOCOL:
            u = ip_pkt.payload
            if not isinstance(u, udp):
                return base
            return "%s | src_port=%s dst_port=%s" % (base, u.srcport, u.dstport)

        if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
            ic = ip_pkt.payload
            if not isinstance(ic, icmp):
                return base
            type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                        8: "Echo Request", 11: "TTL Exceeded"}
            icmp_type_str = type_map.get(ic.type, "type=%d" % ic.type)
            return "%s | icmp_type=%s code=%s" % (base, icmp_type_str, ic.code)

        return base

    return "ETH type=0x%04x | src=%s dst=%s" % (eth.type, eth.src, eth.dst)


class PacketLoggerSwitch(object):

    def __init__(self, connection):
        self.connection = connection
        self.dpid = connection.dpid
        self.mac_to_port = {}
        self.packet_count = 0
        connection.addListeners(self)
        log.info("PacketLogger attached to switch %s" % dpidToStr(self.dpid))
        log_packet(self.dpid, "Switch connected to controller.")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet is None:
            log.warning("Empty packet - ignoring.")
            return

        self.packet_count += 1
        in_port = event.port

        description = describe_packet(packet)
        log_packet(self.dpid, "PKT #%d in_port=%d | %s" % (
            self.packet_count, in_port, description))

        self.mac_to_port[packet.src] = in_port

        if packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[packet.dst]
            log_packet(self.dpid, "  => Forwarding %s -> %s out port %d" % (
                packet.src, packet.dst, out_port))
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, in_port)
            msg.idle_timeout = 30
            msg.hard_timeout = 120
            msg.priority = 10
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data = event.ofp
            self.connection.send(msg)
        else:
            log_packet(self.dpid, "  => Flooding (unknown dst %s)" % packet.dst)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = in_port
            self.connection.send(msg)

    def _handle_ConnectionDown(self, event):
        log_packet(self.dpid, "Switch disconnected. Total packets logged: %d" % self.packet_count)


class PacketLogger(object):

    def __init__(self):
        core.openflow.addListeners(self)
        with open(LOG_FILE, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("  PACKET LOGGER - SDN Controller (POX)\n")
            f.write("  Session started: %s\n" % datetime.now())
            f.write("=" * 70 + "\n\n")
        log.info("Packet Logger started. Logging to '%s'" % os.path.abspath(LOG_FILE))

    def _handle_ConnectionUp(self, event):
        PacketLoggerSwitch(event.connection)


def launch():
    core.registerNew(PacketLogger)
    log.info("Packet Logger component loaded.")
