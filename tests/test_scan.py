import sys
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
from detect import ScanDetector


def syn(ts, src, dport, flags=0x02):
    return {"ts": ts, "src": src, "proto": "TCP", "flags": flags, "dport": dport}


def run(packets):
    d = ScanDetector()
    return [a for a in (d.process(p) for p in packets) if a]


# 1. fast scan: 30 different ports in 0.3 s -> exactly 1 alert
a = run([syn(100 + i * 0.01, "10.0.0.5", 1000 + i) for i in range(30)])
print("fast scan        :", "PASS" if len(a) == 1 else "FAIL", len(a))

# 2. same port 100 times -> not a scan, no alert
a = run([syn(100 + i * 0.01, "10.0.0.5", 80) for i in range(100)])
print("one port repeated:", "PASS" if len(a) == 0 else "FAIL", len(a))

# 3. slow: 30 ports, 2 s apart -> only ~5 ports in any 10 s window, no alert
a = run([syn(100 + i * 2, "10.0.0.5", 1000 + i) for i in range(30)])
print("slow trickle     :", "PASS" if len(a) == 0 else "FAIL", len(a))

# 4. SYN-ACK replies (flags 0x12) from a server are ignored
a = run([syn(100 + i * 0.01, "10.0.0.9", 1000 + i, flags=0x12) for i in range(30)])
print("SYN-ACK ignored  :", "PASS" if len(a) == 0 else "FAIL", len(a))
