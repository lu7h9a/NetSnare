from collections import deque, defaultdict

class ScanDetector:
    def __init__(self, max_ports=20, window=10):
        self.max_ports = max_ports
        self.window = window
        self.history = defaultdict(deque)   # src ip -> deque of (time, dport)
        self.last_alert = {}                # src ip -> time of last alert

    def process(self, pkt):
        if pkt["proto"] != "TCP":
            return None
        if (pkt["flags"] & 0x12) != 0x02:   # SYN set, ACK not set
            return None

        now = pkt["ts"]
        src = pkt["src"]
        q = self.history[src]
        q.append((now, pkt["dport"]))

        while q and now - q[0][0] > self.window:
            q.popleft()

        ports = {p for t, p in q}
        if len(ports) > self.max_ports:
            if now - self.last_alert.get(src, 0) > self.window:
                self.last_alert[src] = now
                return {"type": "PORT_SCAN", "src": src,
                        "ports": len(ports), "window": self.window, "ts": now}
        return None

class SlowScanDetector:
    def __init__(self, max_ports=30, bucket_secs=60, n_buckets=10):
        self.max_ports = max_ports
        self.bucket_secs = bucket_secs
        self.n_buckets = n_buckets
        self.buckets = defaultdict(dict)    # src -> {bucket_id: set of dports}
        self.last_alert = {}

    def process(self, pkt):
        if pkt["proto"] != "TCP" or (pkt["flags"] & 0x12) != 0x02:
            return None

        now = pkt["ts"]
        src = pkt["src"]
        bucket_id = int(now // self.bucket_secs)
        per_src = self.buckets[src]
        per_src.setdefault(bucket_id, set()).add(pkt["dport"])

        oldest = bucket_id - self.n_buckets + 1
        for b in [b for b in per_src if b < oldest]:
            del per_src[b]

        ports = set().union(*per_src.values())
        window = self.bucket_secs * self.n_buckets
        if len(ports) > self.max_ports:
            if now - self.last_alert.get(src, 0) > window:
                self.last_alert[src] = now
                return {"type": "SLOW_PORT_SCAN", "src": src,
                        "ports": len(ports), "window": window, "ts": now}
        return None

class DistributedScanDetector:
    def __init__(self, min_sources=5, max_ports=30, bucket_secs=60, n_buckets=5):
        self.min_sources = min_sources
        self.max_ports = max_ports
        self.bucket_secs = bucket_secs
        self.n_buckets = n_buckets
        self.buckets = defaultdict(dict)    # dst -> {bucket_id: (set of srcs, set of dports)}
        self.last_alert = {}

    def process(self, pkt):
        if pkt["proto"] != "TCP" or (pkt["flags"] & 0x12) != 0x02:
            return None

        now = pkt["ts"]
        dst = pkt["dst"]
        bucket_id = int(now // self.bucket_secs)
        per_dst = self.buckets[dst]
        srcs, ports = per_dst.setdefault(bucket_id, (set(), set()))
        srcs.add(pkt["src"])
        ports.add(pkt["dport"])

        oldest = bucket_id - self.n_buckets + 1
        for b in [b for b in per_dst if b < oldest]:
            del per_dst[b]

        all_srcs = set().union(*(s for s, p in per_dst.values()))
        all_ports = set().union(*(p for s, p in per_dst.values()))
        window = self.bucket_secs * self.n_buckets
        if len(all_srcs) >= self.min_sources and len(all_ports) > self.max_ports:
            if now - self.last_alert.get(dst, 0) > window:
                self.last_alert[dst] = now
                return {"type": "DISTRIBUTED_SCAN", "dst": dst,
                        "sources": len(all_srcs), "ports": len(all_ports),
                        "window": window, "ts": now}
        return None
