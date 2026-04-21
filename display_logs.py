#!/usr/bin/env python3
"""
display_logs.py  -  Parse and display packet_log.txt in a readable table.

Usage:
    python3 display_logs.py [log_file]              # default: packet_log.txt
    python3 display_logs.py packet_log.txt --proto TCP
    python3 display_logs.py packet_log.txt --stats
"""

import re
import sys
import argparse
from collections import Counter, defaultdict

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"

PROTO_COLOR = {
    "TCP":  GREEN,
    "UDP":  CYAN,
    "ICMP": YELLOW,
    "ARP":  BLUE,
    "IPv4": MAGENTA,
    "IPv6": RED,
}

def color_proto(proto):
    c = PROTO_COLOR.get(proto, MAGENTA)
    return f"{c}{BOLD}{proto:6}{RESET}"

LINE_RE = re.compile(
    r"\[(?P<ts>[\d\-: .]+)\]\s+\[Switch (?P<sw>[^\]]+)\]\s+(?P<msg>.*)"
)

def parse_log(path):
    entries = []
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if not m:
                continue
            entries.append({
                "ts":  m.group("ts").strip(),
                "sw":  m.group("sw").strip(),
                "msg": m.group("msg").strip(),
            })
    return entries

def detect_proto(msg):
    for p in ("TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6"):
        if f"| {p}" in msg or f"| {p} " in msg:
            return p
    if "0x86dd" in msg:
        return "IPv6"
    if "0x0800" in msg:
        return "IPv4"
    return "OTHER"

def extract_field(msg, key):
    m = re.search(rf"{re.escape(key)}=([\w.:]+)", msg)
    return m.group(1) if m else "-"

def extract_inport(msg):
    m = re.search(r"in_port=(\d+)", msg)
    return m.group(1) if m else "-"

def extract_src_mac(msg):
    m = re.search(r"src=([\w:]+)", msg)
    return m.group(1) if m else "-"

COL = "{:<26} {:<8} {:<8} {:<15} {:<15} {:<10} {:<10} {}"

def print_header():
    h = COL.format("Timestamp", "Switch", "Proto", "Src IP", "Dst IP",
                    "Src Port", "Dst Port", "Extra")
    print(f"\n{BOLD}{h}{RESET}")
    print("-" * 110)

def print_entry(e):
    msg = e["msg"]
    if not msg.startswith("PKT"):
        return
    proto    = detect_proto(msg)
    src_ip   = extract_field(msg, "src_ip")
    dst_ip   = extract_field(msg, "dst_ip")
    src_port = extract_field(msg, "sport")
    dst_port = extract_field(msg, "dport")

    extra = ""
    fm = re.search(r"flags=\[([^\]]*)\]", msg)
    if fm:
        extra = f"flags=[{fm.group(1)}]"
    im = re.search(r"icmp=([^\|]+)", msg)
    if im:
        extra = im.group(1).strip()

    print(COL.format(
        e["ts"], e["sw"][:6], color_proto(proto),
        src_ip[:15], dst_ip[:15],
        src_port[:10], dst_port[:10],
        extra
    ))

def print_stats(entries):
    proto_count   = Counter()
    src_mac_count = Counter()
    port_count    = Counter()
    flow_count    = Counter()

    for e in entries:
        msg = e["msg"]
        if not msg.startswith("PKT"):
            continue
        proto = detect_proto(msg)
        proto_count[proto] += 1
        src_mac_count[extract_src_mac(msg)] += 1
        port_count[extract_inport(msg)] += 1

        src_ip = extract_field(msg, "src_ip")
        dst_ip = extract_field(msg, "dst_ip")
        if src_ip != "-" and dst_ip != "-":
            flow_count[(src_ip, dst_ip, proto)] += 1

    total = sum(proto_count.values())

    print(f"\n{BOLD}{'=' * 45}")
    print(f"  PACKET STATISTICS  (total packets: {total})")
    print(f"{'=' * 45}{RESET}")

    print(f"\n{BOLD}Protocol Breakdown:{RESET}")
    for proto, cnt in proto_count.most_common():
        pct = cnt * 100 // max(total, 1)
        bar = "#" * (cnt * 30 // max(total, 1))
        print(f"  {color_proto(proto)}  {cnt:>5} ({pct:>3}%)  {bar}")

    print(f"\n{BOLD}Top Source MACs:{RESET}")
    for mac, cnt in src_mac_count.most_common(5):
        print(f"  {mac:<22}  {cnt:>5} packets")

    print(f"\n{BOLD}Packets by In-Port:{RESET}")
    for port, cnt in sorted(port_count.items()):
        print(f"  port {port:<6}  {cnt:>5} packets")

    print(f"\n{BOLD}Top Flows  (src_ip -> dst_ip | proto):{RESET}")
    for (src, dst, proto), cnt in flow_count.most_common(10):
        print(f"  {src:<15} -> {dst:<15}  {color_proto(proto)}  {cnt:>4} pkts")
    print()

def main():
    ap = argparse.ArgumentParser(description="Display POX Packet Logger output")
    ap.add_argument("logfile", nargs="?", default="packet_log.txt")
    ap.add_argument("--proto", help="Filter by protocol: TCP / UDP / ICMP / ARP / IPv4 / IPv6")
    ap.add_argument("--stats", action="store_true", help="Show statistics only")
    args = ap.parse_args()

    try:
        entries = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: '{args.logfile}' not found. Run the simulation first.")
        sys.exit(1)

    if args.stats:
        print_stats(entries)
        return

    print_header()
    for e in entries:
        msg = e["msg"]
        if not msg.startswith("PKT"):
            continue
        # BUG FIX: filter by detected protocol, not by startswith(proto)
        if args.proto and detect_proto(msg).upper() != args.proto.upper():
            continue
        print_entry(e)

    print_stats(entries)

if __name__ == "__main__":
    main()
