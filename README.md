# netmon

A real-time network flow analyzer and anomaly detector written in C using libpcap. Captures live traffic, tracks bidirectional flows in a hash table, runs four behavioral anomaly detectors concurrently, and exports flow data to CSV on exit.

## What it does

**Flow tracking**

- Parses Ethernet → IPv4 → TCP/UDP at the packet level
- Maintains a 4096-slot open-addressing hash table of active flows (FNV-1a hashing, tombstone deletion for probe chain integrity)
- Bidirectional normalization: A→B and B→A map to the same flow entry
- Tracks TX and RX bytes separately to distinguish upload vs download direction
- Expires stale flows every 30 seconds via SIGALRM - no per-packet timestamp checks
- Live table display sorted by byte count, updated once per second
- Stale flows (silent > 3s) marked with `~` so historical BPS values are visually distinct

**Anomaly detection** (`analysis.c`)

| Detector | Trigger | Default threshold |
|---|---|---|
| Port scan | Single source probes > 20 distinct dst ports in 60s | `SCAN_PORT_THRESHOLD` |
| SYN flood | Single source opens > 80 new TCP flows in 10s | `FLOOD_FLOW_THRESHOLD` |
| Data exfiltration | Flow TX > 5× RX and total > 1 MB | `EXFIL_RATIO` |
| Elephant flow | Single flow exceeds 10% of total session bytes and > 512 KB | `ELEPHANT_THRESHOLD` |

All thresholds are `#define` constants at the top of `analysis.c`.

**CSV export on exit**

When you press Ctrl+C, all active flows are written to a timestamped CSV file (e.g. `netmon_20260519_162233.csv`). Fields: src/dst IP and port, protocol, packet count, total/TX/RX bytes, first/last seen epoch, duration in seconds. Each run produces a new file - no history is overwritten.

## Build

```bash
# Debian/Ubuntu/Kali
sudo apt install libpcap-dev

make
```

## Usage

```bash
# Specify interface directly
sudo ./netmon eth0

# Or let it list interfaces and prompt
sudo ./netmon
```

Requires root (or `CAP_NET_RAW`) to open a live capture. Press Ctrl+C to stop - prints a final flow snapshot and exports CSV on exit.

## Example output

```
==== NETMON | flows: 30 | 16:11:27 ====

Protocol Breakdown:
  TCP:   94.86%
  UDP:    5.14%
  DNS:    0.64%
  HTTPS: 98.34%

  SRC                    DST                    PROTO  PKTS     TX         RX         DURATION     BPS
  104.18.4.159:443       10.0.2.15:53902        HTTPS  263      228.8 KB   22.7 KB    00:00:03     686787
  104.18.4.159:443       10.0.2.15:53922        HTTPS  98       122.5 KB   4.4 KB     00:00:00     1039544  ~
  142.251.221.202:443    10.0.2.15:48006        QUIC   17       6.5 KB     5.3 KB     00:00:00     96784    ~

[!] ELEPHANT FLOW  104.18.4.159:443 → 10.0.2.15:53902  228.8 KB  (38.4% of session traffic)

[+] flows exported to netmon_20260519_161127.csv
```

## Architecture

```
main.c          entry point, interface selection
capture.c       pcap loop, SIGINT/SIGALRM handlers, CSV export trigger
parser.c        Ethernet/IP/TCP/UDP header parsing
flow.h / flow.c hash table, flow lifecycle, TX/RX accounting, display
analysis.h / analysis.c   port scan, SYN flood, exfil, elephant flow detectors
Makefile        single-command build, no intermediate object files
```

Detection logic is decoupled from flow tracking via an observer callback. `flow.c` calls a registered function after each packet update, passing the raw (pre-normalization) source IP and destination port. `analysis.c` registers its four detectors there -`flow.c` has no knowledge of detection logic.

## Notable implementation details

- **Hash table design** - open addressing with linear probing and tombstone deletion. Tombstones preserve probe chain integrity after deletions without requiring rehashing. Load factor capped at 70% to bound worst-case probe length
- **Bidirectional normalization** - flows are keyed on the canonical (lower IP, lower port) tuple so A→B and B→A always map to the same entry. TX/RX accounting uses the pre-normalization source to correctly attribute direction
- **SIGALRM expiry** - stale flow expiry runs on a timer signal rather than checking timestamps on every packet, avoiding a `time()` syscall per packet at high traffic rates
- **Stack frame fix** - `print_flows` originally allocated `flow_t sorted[4096]` (~180 KB) on the stack; changed to `static` to avoid stack exhaustion on busy interfaces
- **Dangling pointer fix** - original `main.c` called `pcap_freealldevs()` before passing `dev` (a pointer into the freed list) to `pcap_open_live()`. Fixed by copying the device name into a local buffer before freeing
