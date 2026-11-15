# Changelog

All notable changes to NetSnare are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Renamed from NetWraith to NetSnare.
- The dashboard is served by `serve.py` instead of `python3 -m http.server`:
  it serves only `dashboard.html` and `alerts.json`, refuses foreign `Host`
  headers (DNS rebinding) and never runs as root.
- Outputs moved: `www/alerts.json`, and `logs/packets.jsonl` (owner-only,
  rotated at 100 MB).
- The sniffer and the dashboard server drop root after start-up.

### Fixed
- Scan detectors now do constant work per packet; before, a flood made each
  packet slower than the last.
- Memory is bounded under spoofed traffic: every detector caps and sweeps
  its keys, and the alert list keeps the last 200.
- IP fragments, IHL below 5, non-IPv4 and short TCP headers are no longer
  decoded as TCP (forged SYNs, hidden scans).
- A bogus ACK after each SYN no longer hides a SYN flood; a spoofed flood
  spread over random ports now trips a per-host limit.
- On loopback each packet is counted once, not twice.
- A full disk no longer stops the sniffer.

### Added
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and CI
  that runs the unit tests on every push.
- `tests/test_hardening.py` (20 checks).

## [0.1.0] - 2026-11-11

First working version.

### Added
- Raw `AF_PACKET` capture with hand-written decoding of Ethernet, IPv4, TCP
  and UDP headers (`struct.unpack`, no third-party libraries).
- `packets.jsonl`: one JSON line per decoded packet.
- Four detectors:
  - a fast port-scan detector (10-second sliding window);
  - a slow port-scan detector (1-minute buckets over 10 minutes);
  - a distributed port-scan detector (many sources against one target);
  - a SYN-flood detector (per service and global, which also catches
    spoofed floods).
- Atomic `alerts.json` writes, and `dashboard.html`, a live alert table with
  light and dark themes.
- `run.sh`, a one-command launcher for the sniffer and the dashboard server.
- Unit tests for every detector (22 checks), plus a live attack harness
  (`tests/attack.sh`).

### Fixed
- `write_state`: removed a duplicate function, and the temp file name now
  includes the process id.

[Unreleased]: https://github.com/lu7h9a/netsnaire/commits/main
[0.1.0]: https://github.com/lu7h9a/netsnaire/commit/0800475
