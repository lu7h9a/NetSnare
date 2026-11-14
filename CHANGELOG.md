# Changelog

All notable changes to NetWraith are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and CI
  that runs the unit tests on every push.

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

[Unreleased]: https://github.com/lu7h9a/netwraith/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lu7h9a/netwraith/commits/main
