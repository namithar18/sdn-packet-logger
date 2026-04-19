#!/usr/bin/env python3
"""
display_logs.py  –  Parse and display packet_log.txt in a readable table.

Usage:
    python3 display_logs.py [log_file]        # default: packet_log.txt
    python3 display_logs.py packet_log.txt --proto TCP
    python3 display_logs.py packet_log.txt --stats
"""

import re
import sys
import argparse
from collections import Counter, defaultdict


# ── ANSI colours ────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
BLUE   = "\033[34m"
MAGENTA = "\033[35m"

PROTO_COLOR = {
    "TCP":  GREEN,
    "UDP":  CYAN,
    "ICMP": YELLOW,
    "ARP":  BLUE,
}


def color_proto(proto):
    c = PROTO_COLOR.get(proto, MAGENTA)
    return f"{c}{BOLD}{proto:6}{RESET}"


# ── Log line parser ──────────────────────────────────────────────────
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
    for p in ("TCP", "UDP", "ICMP", "ARP"):
        if msg.startswith(p):
            return p
    return "OTHER"


def extract_field(msg, key):
    """Pull 'key=value' from a log message."""
    m = re.search(rf"{re.escape(key)}=([\w.:]+)", msg)
    return m.group(1) if m else "-"


# ── Display functions ────────────────────────────────────────────────
COL = "{:<26} {:<8} {:<8} {:<15} {:<15} {:<10} {:<10} {}"

def print_header():
    h = COL.format("Timestamp", "Switch", "Proto", "Src IP", "Dst IP",
                    "Src Port", "Dst Port", "Extra")
    print(f"\n{BOLD}{h}{RESET}")
    print("─" * 110)


def print_entry(e):
    msg   = e["msg"]
    proto = detect_proto(msg)

    # Only print PKT lines (skip forwarding/flood meta lines)
    if not msg.startswith("PKT"):
        return

    src_ip   = extract_field(msg, "src_ip")
    dst_ip   = extract_field(msg, "dst_ip")
    src_port = extract_field(msg, "src_port")
    dst_port = extract_field(msg, "dst_port")
    in_port  = extract_field(msg, "in_port")

    # Extra info: flags for TCP, icmp_type for ICMP
    extra = ""
    fm = re.search(r"flags=\[([^\]]*)\]", msg)
    if fm:
        extra = f"flags=[{fm.group(1)}]"
    im = re.search(r"icmp_type=([^\|]+)", msg)
    if im:
        extra = im.group(1).strip()

    row = COL.format(
        e["ts"], e["sw"][:6], color_proto(proto),
        src_ip[:15], dst_ip[:15],
        src_port[:10], dst_port[:10],
        extra
    )
    print(row)


def print_stats(entries):
    proto_count  = Counter()
    src_ip_count = Counter()
    flow_count   = Counter()

    for e in entries:
        msg = e["msg"]
        if not msg.startswith("PKT"):
            continue
        proto = detect_proto(msg)
        proto_count[proto] += 1
        src_ip = extract_field(msg, "src_ip")
        dst_ip = extract_field(msg, "dst_ip")
        src_ip_count[src_ip] += 1
        if src_ip != "-" and dst_ip != "-":
            flow_count[(src_ip, dst_ip, proto)] += 1

    total = sum(proto_count.values())

    print(f"\n{BOLD}{'─'*40}")
    print(f"  PACKET STATISTICS  (total: {total})")
    print(f"{'─'*40}{RESET}")

    print(f"\n{BOLD}By Protocol:{RESET}")
    for proto, cnt in proto_count.most_common():
        bar = "█" * (cnt * 30 // max(total, 1))
        print(f"  {color_proto(proto)}  {cnt:>5}  {bar}")

    print(f"\n{BOLD}Top Source IPs:{RESET}")
    for ip, cnt in src_ip_count.most_common(10):
        print(f"  {ip:<18} {cnt:>5} packets")

    print(f"\n{BOLD}Top Flows (src → dst | proto):{RESET}")
    for (src, dst, proto), cnt in flow_count.most_common(10):
        print(f"  {src:<16} → {dst:<16}  {color_proto(proto)}  {cnt:>4} pkts")

    print()


# ── Main ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Display POX Packet Logger output")
    ap.add_argument("logfile", nargs="?", default="packet_log.txt")
    ap.add_argument("--proto",  help="Filter by protocol (TCP/UDP/ICMP/ARP)")
    ap.add_argument("--stats",  action="store_true", help="Show statistics summary")
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
        if args.proto and not e["msg"].startswith(args.proto):
            continue
        print_entry(e)

    # Always show mini-stats at the end
    print_stats(entries)


if __name__ == "__main__":
    main()
