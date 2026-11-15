import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detect import ScanDetector, SlowScanDetector


def syn(ts, src, dport):
    return {"ts": ts, "src": src, "proto": "TCP", "flags": 0x02, "dport": dport}


def alerts(detector, packets):
    return [a for a in (detector.process(p) for p in packets) if a]


# 1. trickle: 40 ports, one every 5 s (200 s total)
pk = [syn(6000 + i * 5, "10.0.0.5", 1000 + i) for i in range(40)]
fast = alerts(ScanDetector(), pk)
slow = alerts(SlowScanDetector(), pk)
print("trickle, fast detector:", "PASS" if len(fast) == 0 else "FAIL", len(fast))
print("trickle, slow detector:", "PASS" if len(slow) == 1 else "FAIL", len(slow))

# 2. far too slow: 40 ports, one every 30 s (20 min) -> escapes, an honest limit
pk = [syn(6000 + i * 30, "10.0.0.5", 1000 + i) for i in range(40)]
n = len(alerts(SlowScanDetector(), pk))
print("20-min trickle missed :", "PASS" if n == 0 else "FAIL", n)

# 3. same port every 6 s -> no alert
pk = [syn(6000 + i * 6, "10.0.0.5", 80) for i in range(100)]
n = len(alerts(SlowScanDetector(), pk))
print("one port repeated     :", "PASS" if n == 0 else "FAIL", n)

# 4. memory stays bounded: 1 hour of traffic, at most 10 buckets kept
d = SlowScanDetector()
for i in range(360):
    d.process(syn(6000 + i * 10, "10.0.0.5", 1000 + i))
kept = len(d.buckets["10.0.0.5"].buckets)
print("buckets kept <= 10    :", "PASS" if kept <= 10 else "FAIL", kept)
