import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detect import ScanDetector, FloodDetector


def tcp(ts, src, sport, dst, dport, flags):
    return {"ts": ts, "src": src, "sport": sport, "dst": dst,
            "dport": dport, "proto": "TCP", "flags": flags}


def alerts(detector, packets):
    return [a for a in (detector.process(p) for p in packets) if a]


# 1. one source, 300 SYNs at port 80 in 3 s, never completed
pk = [tcp(6000 + i * 0.01, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02) for i in range(300)]
n = len(alerts(FloodDetector(), pk))
print("flood, one source      :", "PASS" if n == 1 else "FAIL", n)

# 2. spoofed flood: 600 SYNs from 600 different sources
pk = [tcp(6000 + i * 0.005, "10.1.%d.%d" % (i // 250, i % 250 + 1), 30000, "10.0.0.9", 80, 0x02)
      for i in range(600)]
a = alerts(FloodDetector(), pk)
print("flood, spoofed sources :", "PASS" if len(a) == 1 and a[0]["src"] == "many" else "FAIL", len(a))

# 3. normal clients: 200 handshakes, each SYN followed by its ACK
pk = []
for i in range(200):
    t = 6000 + i * 0.01
    pk.append(tcp(t, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02))
    pk.append(tcp(t + 0.005, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x10))
n = len(alerts(FloodDetector(), pk))
print("normal handshakes      :", "PASS" if n == 0 else "FAIL", n)

# 4. port scan: 1000 SYNs to 1000 different ports -> scan alert, NOT a flood
pk = [tcp(6000 + i * 0.001, "10.0.0.5", 20000 + i, "10.0.0.9", 1 + i, 0x02) for i in range(1000)]
s = len(alerts(ScanDetector(), pk))
f = len(alerts(FloodDetector(), pk))
print("scan seen as scan      :", "PASS" if s == 1 else "FAIL", s)
print("scan not seen as flood :", "PASS" if f == 0 else "FAIL", f)

# 5. slow SYNs: 150 SYNs, one every 0.5 s -> at most 10 in any 5 s window
pk = [tcp(6000 + i * 0.5, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02) for i in range(150)]
n = len(alerts(FloodDetector(), pk))
print("slow SYNs              :", "PASS" if n == 0 else "FAIL", n)

# 6. memory: after the flood stops, old half-open entries are forgotten
d = FloodDetector()
for p in [tcp(6000 + i * 0.01, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02) for i in range(300)]:
    d.process(p)
d.process(tcp(6020, "10.0.0.5", 1, "10.0.0.9", 80, 0x02))
print("entries kept == 1      :", "PASS" if len(d.pending) == 1 else "FAIL", len(d.pending))
