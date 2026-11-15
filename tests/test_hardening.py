"""Tests for the final-review fixes: bounded memory, constant work per
packet, handshake checks, strict decoding and the dashboard server.
Needs no root and no network beyond a 127.0.0.1 socket."""
import http.client
import os
import struct
import sys
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from detect import ScanDetector, SlowScanDetector, DistributedScanDetector, FloodDetector
from sniffer import parse_packet
import serve


def check(name, ok, detail=""):
    print("%-38s:" % name, "PASS" if ok else "FAIL", detail)


def tcp(ts, src, sport, dst, dport, flags, seq=None):
    p = {"ts": ts, "src": src, "sport": sport, "dst": dst,
         "dport": dport, "proto": "TCP", "flags": flags}
    if seq is not None:
        p["seq"] = seq
    return p


def spoofed(i):
    return "10.%d.%d.%d" % (i // 65536 % 256, i // 256 % 256, i % 256)


# 1-2. work per packet does not grow with the backlog (was 37 s / 65 s for 80k)
d = ScanDetector()
t0 = time.time()
for i in range(100_000):
    d.process(tcp(i * 0.0001, "10.0.0.5", 1000, "10.0.0.9", 1 + i % 60000, 0x02))
el = time.time() - t0
check("scan: 100k SYN flood under 5 s", el < 5, "%.2fs" % el)

d = DistributedScanDetector()
t0 = time.time()
for i in range(100_000):
    d.process(tcp(i * 0.0001, spoofed(i), 1000, "10.0.0.9", 1 + i % 60000, 0x02))
el = time.time() - t0
check("distributed: 100k spoofed under 5 s", el < 5, "%.2fs" % el)

# 3. the number of tracked sources is capped
d = ScanDetector(max_keys=1000)
for i in range(20_000):
    d.process(tcp(i * 0.001, spoofed(i), 1, "10.0.0.9", 80, 0x02))
check("scan: tracked sources capped", len(d.history) == 1000, len(d.history))

# 4. idle sources are forgotten by sweep
d = SlowScanDetector()
for i in range(5000):
    d.process(tcp(100 + i * 0.001, spoofed(i), 1, "10.0.0.9", 80, 0x02))
d.sweep(100 + 3600)
check("slow: sweep forgets idle sources", len(d.buckets) == 0, len(d.buckets))

# 5. half-open table is capped under a spoofed flood
d = FloodDetector(max_keys=1000)
for i in range(20_000):
    d.process(tcp(i * 0.0001, spoofed(i), 4000, "10.0.0.9", 80, 0x02))
check("flood: half-open table capped", len(d.pending) <= 1000, len(d.pending))

# 6. an ACK that does not continue the SYN does not clear it
d = FloodDetector()
n = 0
for i in range(300):
    t = 6000 + i * 0.01
    n += bool(d.process(tcp(t, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02, seq=1000)))
    n += bool(d.process(tcp(t + 0.001, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x10, seq=5)))
check("flood: bogus ACKs still a flood", n == 1, n)

# 7. the real final ACK (seq = SYN seq + 1) clears it
d = FloodDetector()
n = 0
for i in range(300):
    t = 6000 + i * 0.01
    n += bool(d.process(tcp(t, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x02, seq=0xFFFFFFFF)))
    n += bool(d.process(tcp(t + 0.001, "10.0.0.5", 20000 + i, "10.0.0.9", 80, 0x10, seq=0)))
check("flood: real handshakes (seq wrap) quiet", n == 0, n)

# 8. a spoofed flood spread over random ports trips the per-host limit
d = FloodDetector()
a = [x for x in (d.process(tcp(6000 + i * 0.001, spoofed(i), 5000, "10.0.0.9", 1 + i, 0x02))
                 for i in range(1500)) if x]
check("flood: random-port flood per host", len(a) == 1 and a[0]["dport"] == "many", len(a))


# --- decoding --------------------------------------------------------------
def frame(ver_ihl=0x45, frag=0, proto=6, tcp_off=0x50, flags=0x02, trunc=None):
    tcp_hdr = struct.pack("!HHIIBBHHH", 1234, 80, 1, 0, tcp_off, flags, 512, 0, 0)
    ihl = (ver_ihl & 0x0F) * 4
    opts = b"\0" * max(0, ihl - 20)
    total = 20 + len(opts) + len(tcp_hdr)
    ip = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 1, frag, 64, proto, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    data = b"\0" * 12 + b"\x08\x00" + ip + opts + tcp_hdr
    return data[:trunc] if trunc else data


p = parse_packet(frame(), ts=1)
check("decode: plain SYN", p and p["proto"] == "TCP" and p["flags"] == 2 and p["dport"] == 80)
p = parse_packet(frame(frag=0x0003), ts=1)
check("decode: non-first fragment not TCP", p and p["proto"] == "FRAG")
p = parse_packet(frame(frag=0x2000), ts=1)
check("decode: first fragment counted", p and p["proto"] == "FRAG")
check("decode: IHL < 5 rejected", parse_packet(frame(ver_ihl=0x41), ts=1) is None)
check("decode: IPv6 version rejected", parse_packet(frame(ver_ihl=0x65), ts=1) is None)
check("decode: TCP offset < 5 rejected", parse_packet(frame(tcp_off=0x10), ts=1) is None)
check("decode: truncated TCP rejected", parse_packet(frame(trunc=40), ts=1) is None)
p = parse_packet(frame(ver_ihl=0x46), ts=1)
check("decode: IP options skipped", p and p["proto"] == "TCP" and p["dport"] == 80)

# --- dashboard server --------------------------------------------------------
os.chdir(ROOT)
serve.Handler.log_message = lambda *a: None
srv = serve.http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", path, skip_host=True)
    c.putheader("Host", host or "127.0.0.1:%d" % port)
    c.endheaders()
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


check("serve: dashboard served", get("/dashboard.html") == 200)
check("serve: packet log not served",
      get("/packets.jsonl") == 404 and get("/logs/packets.jsonl") == 404)
check("serve: repo files not served", get("/.git/config") == 404 and get("/sniffer.py") == 404)
check("serve: foreign Host refused (rebinding)", get("/dashboard.html", "evil.example:%d" % port) == 421)
srv.shutdown()
