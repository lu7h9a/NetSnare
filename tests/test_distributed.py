import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detect import ScanDetector, SlowScanDetector, DistributedScanDetector


def syn(ts, src, dst, dport):
    return {"ts": ts, "src": src, "dst": dst, "proto": "TCP", "flags": 0x02, "dport": dport}


def alerts(detector, packets):
    return [a for a in (detector.process(p) for p in packets) if a]


# 1. six sources, six ports each (36 ports in total) against one target, 108 s
pk = [syn(6000 + (s * 6 + k) * 3, "10.0.1.%d" % (s + 1), "10.0.0.9", 1000 + s * 6 + k)
      for s in range(6) for k in range(6)]
n = len(alerts(ScanDetector(), pk))
print("distributed, fast detector :", "PASS" if n == 0 else "FAIL", n)
n = len(alerts(SlowScanDetector(), pk))
print("distributed, slow detector :", "PASS" if n == 0 else "FAIL", n)
n = len(alerts(DistributedScanDetector(), pk))
print("distributed, new detector  :", "PASS" if n == 1 else "FAIL", n)

# 2. only two sources, 20 ports each (40 ports) -> fewer than 5 sources
pk = [syn(6000 + (s * 20 + k) * 3, "10.0.1.%d" % (s + 1), "10.0.0.9", 1000 + s * 20 + k)
      for s in range(2) for k in range(20)]
n = len(alerts(DistributedScanDetector(), pk))
print("2 sources only             :", "PASS" if n == 0 else "FAIL", n)

# 3. 50 different clients all connecting to port 443 -> a busy web server
pk = [syn(6000 + i, "10.0.2.%d" % (i + 1), "10.0.0.9", 443) for i in range(50)]
n = len(alerts(DistributedScanDetector(), pk))
print("50 clients, one port       :", "PASS" if n == 0 else "FAIL", n)

# 4. memory stays bounded: 1 hour of traffic, at most 5 buckets kept
d = DistributedScanDetector()
for i in range(360):
    d.process(syn(6000 + i * 10, "10.0.3.%d" % (i % 200 + 1), "10.0.0.9", 1000 + i))
kept = len(d.buckets["10.0.0.9"])
print("buckets kept <= 5          :", "PASS" if kept <= 5 else "FAIL", kept)
