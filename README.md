# NetWraith

A packet sniffer and intrusion detector for Linux, built from scratch in Python 3 with **no frameworks** — no Scapy, no Flask, no third-party dependencies. Raw sockets, hand-decoded Ethernet/IPv4/TCP/UDP headers, and four independent detection algorithms for port scans and SYN floods.

![dashboard screenshot placeholder](docs/screenshot-placeholder.png)
*(screenshot: replace with a real capture of `dashboard.html` showing a live alert)*

**Full write-up, architecture diagram, byte-by-byte packet walkthrough, real test results, and an interview-prep kit:** [docs/BUILD-GUIDE.html](docs/BUILD-GUIDE.html)

## Why this exists

Most "packet sniffer" projects lean on a library (Scapy, dpkt) that hides exactly the part worth learning. NetWraith decodes every header field by hand with `struct.unpack` — down to testing a single TCP flag bit with a bitmask — so each line can be explained, not just imported.

It turned out to be useful for more than that:

- **A lightweight home/lab network monitor** — no install beyond Python 3's standard library, runs from one folder, shows alerts in any browser on the LAN.
- **A teaching artifact** for networking courses — every byte offset in a real captured packet is documented in the build guide.
- **A blue-team baseline for CTF practice** — the JSON alert feed is trivial to pipe into a scoreboard or webhook.
- **A base for IDS research** — the four detector classes are small, independently unit-tested, and built to be swapped or extended rather than inherited from a framework.

## How it works, in 5 lines

1. `sniffer.py` opens a raw `AF_PACKET`/`SOCK_RAW` socket and reads packets as they arrive.
2. `parse_packet()` decodes the Ethernet, IPv4, and TCP/UDP headers by hand into a plain dict.
3. Every packet is handed to four detectors: a fast port-scan detector (sliding 10s window), a slow bucketed one (10-minute window for patient scanners), a distributed one (groups by *victim*, not attacker, to catch many-IP scans), and a SYN-flood detector (per-service and global, to catch both single-IP and spoofed floods).
4. Any alert is appended to `alerts.json`, written atomically (temp file + `os.replace`) so readers never see a half-written file.
5. `dashboard.html` polls `alerts.json` every 2 seconds and renders a live table, in light or dark theme.

## Running it

```bash
# find your interface
ip link

# start the sniffer (needs root for the raw socket)
sudo python3 sniffer.py

# in another terminal, serve the dashboard
python3 -m http.server --bind 127.0.0.1 8000

# open http://127.0.0.1:8000/dashboard.html
```

Detection thresholds are constructor defaults in `detect.py` (e.g. `ScanDetector(max_ports=20, window=10)`) — tune them for your own network's traffic volume.

## Tested with

- `tests/test_scan.py`, `test_slow.py`, `test_distributed.py`, `test_flood.py` — synthetic-packet unit tests, all passing.
- Real `nmap -sS` scans and bounded `hping3 --flood` SYN floods against the author's own machine — **5/5 floods caught, 0 false alarms** (full numbers in the build guide).

## Known limitations

See [docs/BUILD-GUIDE.html](docs/BUILD-GUIDE.html) → *Testing & Results* / *Interview Kit* for the full, honest list — including that patient low-and-slow scanners can evade the current thresholds, only SYN-based TCP scans are detected (FIN/NULL/Xmas/ACK and UDP scans are not), and IPv6 is not yet decoded.

## Stack

Python 3 standard library only: `socket`, `struct`, `json`, `collections`, `time`. No external dependencies, no pip install required.
