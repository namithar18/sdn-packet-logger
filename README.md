# Packet Logger using SDN Controller
### UE24CS252B – Computer Networks | Project 5

---

## Problem Statement

Design and implement an SDN-based **Packet Logger** using **Mininet** and the **POX OpenFlow controller** that:

- Captures packet headers traversing the network via `packet_in` controller events
- Identifies protocol types: ARP, ICMP (ping), TCP, UDP
- Maintains timestamped logs in `packet_log.txt`
- Displays packet information (src/dst IP, ports, flags, protocol) in the terminal
- Installs flow rules for known unicast flows (learning switch behaviour)

---

## Architecture

```
  h1 (10.0.0.1)
      |
     s1 ──── h3 (10.0.0.3)        POX Controller (127.0.0.1:6633)
      |              |                      │
  h2 (10.0.0.2)   OVS switch  ─────────────┘ (OpenFlow 1.0)
```

### How it works

1. Every new flow hits the controller via a `packet_in` event.
2. The controller **logs** the packet headers and **learns** the source MAC→port mapping.
3. If the destination MAC is known → unicast forward + install a **flow rule** (idle_timeout=30s, hard_timeout=120s).
4. If destination unknown → **flood**.
5. All logged data is written to `packet_log.txt` and printed to the terminal.

---

## Files

| File | Description |
|------|-------------|
| `packet_logger.py` | POX controller component (place inside `pox/ext/`) |
| `custom_topology.py` | Mininet topology + automated test scenarios |
| `display_logs.py` | Log viewer / statistics tool |

---

## Setup & Execution

### Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Mininet
sudo apt install mininet -y

# Install POX (Python 3 branch)
cd ~
git clone https://github.com/noxrepo/pox.git
cd pox
git checkout fangtooth      # Python 3 compatible branch
```

### Step 1 – Copy the controller

```bash
cp packet_logger.py ~/pox/ext/
```

### Step 2 – Start the POX controller (Terminal 1)

```bash
cd ~/pox
./pox.py log.level --DEBUG packet_logger
```

You should see:
```
INFO:packet_logger:Packet Logger started. Logging to '.../packet_log.txt'
INFO:openflow.of_01:Listening on 0.0.0.0:6633
```

### Step 3 – Start the Mininet topology (Terminal 2)

```bash
sudo python3 custom_topology.py
```

This will:
- Create the topology (1 switch, 3 hosts)
- Run 4 automated test scenarios (ICMP, TCP iperf, UDP iperf, HTTP)
- Drop into the Mininet CLI for manual testing

### Step 4 – Manual CLI commands

```
mininet> pingall                  # ICMP test
mininet> h1 ping -c 3 h2          # ping specific hosts
mininet> h2 iperf -s &            # start iperf server
mininet> h1 iperf -c 10.0.0.2 -t 5   # TCP throughput test
mininet> h1 iperf -c 10.0.0.2 -u -t 5  # UDP test
mininet> sh ovs-ofctl dump-flows s1   # view installed flow rules
mininet> exit
```

### Step 5 – View logs

```bash
# Pretty-printed table
python3 display_logs.py packet_log.txt

# Filter by protocol
python3 display_logs.py packet_log.txt --proto TCP
python3 display_logs.py packet_log.txt --proto ICMP

# Statistics summary only
python3 display_logs.py packet_log.txt --stats
```

---

## Expected Output

### Controller terminal (POX)
```
INFO:packet_logger:[2025-...] [Switch 00-00-...] Switch connected to controller.
INFO:packet_logger:[2025-...] [Switch 00-00-...] PKT #1 in_port=1 | ARP REQUEST | src_mac=00:00:00:00:00:01 ...
INFO:packet_logger:[2025-...] [Switch 00-00-...] PKT #2 in_port=1 | ICMP | src_ip=10.0.0.1 dst_ip=10.0.0.2 | icmp_type=Echo Request
```

### packet_log.txt (excerpt)
```
======================================================================
  PACKET LOGGER – SDN Controller (POX)
  Session started: 2025-xx-xx xx:xx:xx
======================================================================

[2025-xx-xx xx:xx:xx.xxx] [Switch 00-00-00-00-00-01] Switch connected to controller.
[2025-xx-xx xx:xx:xx.xxx] [Switch 00-00-00-00-00-01] PKT #1 in_port=1 | ARP REQUEST | ...
[2025-xx-xx xx:xx:xx.xxx] [Switch 00-00-00-00-00-01] PKT #2 in_port=1 | ICMP | src_ip=10.0.0.1 dst_ip=10.0.0.2 | icmp_type=Echo Request code=0
[2025-xx-xx xx:xx:xx.xxx] [Switch 00-00-00-00-00-01] PKT #3 in_port=1 | TCP | src_ip=10.0.0.1 dst_ip=10.0.0.2 | src_port=54321 dst_port=5001 | flags=[SYN]
```

### display_logs.py statistics output
```
──────────────────────────────────────
  PACKET STATISTICS  (total: 87)
──────────────────────────────────────

By Protocol:
  TCP     48  ████████████████████
  ICMP    25  ██████████
  ARP     10  ████
  UDP      4  █

Top Flows (src → dst | proto):
  10.0.0.1         → 10.0.0.2          TCP     32 pkts
  10.0.0.2         → 10.0.0.1          TCP     16 pkts
  10.0.0.1         → 10.0.0.2          ICMP     8 pkts
```

---

## Test Scenarios

| # | Scenario | Tools Used | What to observe |
|---|----------|-----------|-----------------|
| 1 | ICMP ping between all hosts | `pingall` | ARP + ICMP Echo Request/Reply logged; 0% packet loss |
| 2 | TCP throughput h1 → h2 | `iperf` | SYN/ACK flags logged; flow rules installed; throughput reported |
| 3 | UDP traffic h3 → h1 | `iperf -u` | UDP packets logged with src/dst ports |
| 4 | HTTP request h1 → h2 | `curl` / `python3 -m http.server` | TCP connection setup visible; HTTP port 8080 |

---

## Key SDN Concepts Demonstrated

| Concept | Where |
|---------|-------|
| `packet_in` event handling | `_handle_PacketIn` in `packet_logger.py` |
| Match–action flow rule installation | `ofp_flow_mod` with `ofp_match.from_packet()` |
| MAC learning (reactive forwarding) | `mac_to_port` dictionary |
| Flow timeouts | `idle_timeout=30`, `hard_timeout=120` |
| Protocol identification | `describe_packet()` – ARP/ICMP/TCP/UDP |
| Packet flooding (unknown dst) | `ofp_action_output(port=OFPP_FLOOD)` |

---

## References

1. POX Documentation – https://noxrepo.github.io/pox-doc/html/
2. Mininet Walkthrough – https://mininet.org/walkthrough/
3. OpenFlow 1.0 Specification – https://opennetworking.org/
4. POX GitHub – https://github.com/noxrepo/pox
5. Mininet GitHub – https://github.com/mininet/mininet
