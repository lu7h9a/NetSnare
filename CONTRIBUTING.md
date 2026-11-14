# Contributing

Thanks for your interest in improving NetWraith.

## Ground rules

- **Standard library only.** NetWraith deliberately has no third-party
  dependencies: no Scapy, no Flask, no `pip install`. Please keep it that way.
- **Python 3**, Linux (raw `AF_PACKET` sockets).
- Keep detectors independent and their memory bounded. Each detector has a
  test that proves its memory stays capped.

## Running the tests

The unit tests feed synthetic packets to the detectors and need neither root
nor a network:

```bash
for t in tests/test_*.py; do python3 "$t"; done
```

Every line must say `PASS`; there are 22 checks. CI runs the same tests on
every push and pull request and fails on any `FAIL`.

`tests/attack.sh` drives live attacks (nmap, hping3) against your own
machine. Run it only on a machine you own, never against anyone else's.

## Making a change

1. Fork the repository and create a branch.
2. Make your change. Add or update a test in `tests/` for any change to a
   detector.
3. Run the tests as above.
4. Describe what you changed and why in the pull request. If it changes
   what is detected, say how you tested it.

For security problems, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
