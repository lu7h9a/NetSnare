from collections import Counter, OrderedDict, deque

# Hard cap on the number of keys (sources, destinations, connections) each
# detector tracks. Spoofed traffic can invent a new key per packet, so
# without a cap memory would grow until the process is killed. When the cap
# is reached the least recently seen key is forgotten.
MAX_KEYS = 50_000


class _LRU(OrderedDict):
    """A dict that forgets its least recently used key beyond max_keys."""

    def __init__(self, factory, max_keys=MAX_KEYS):
        super().__init__()
        self.factory = factory
        self.max_keys = max_keys

    def touch(self, key):
        if key in self:
            self.move_to_end(key)
            return self[key]
        value = self[key] = self.factory()
        if len(self) > self.max_keys:
            self.popitem(last=False)
        return value

    def drop_idle(self, is_idle):
        for key in [k for k, v in self.items() if is_idle(v)]:
            del self[key]


def _is_syn(pkt):
    return pkt["proto"] == "TCP" and (pkt["flags"] & 0x12) == 0x02   # SYN set, ACK not set


class _SrcState:
    __slots__ = ("events", "ports", "last_alert")

    def __init__(self):
        self.events = deque()     # (time, dport)
        self.ports = Counter()    # dport -> SYNs to it inside the window
        self.last_alert = 0


class ScanDetector:
    def __init__(self, max_ports=20, window=10, max_keys=MAX_KEYS):
        self.max_ports = max_ports
        self.window = window
        self.history = _LRU(_SrcState, max_keys)   # src ip -> _SrcState

    def process(self, pkt):
        if not _is_syn(pkt):
            return None
        now = pkt["ts"]
        src = pkt["src"]
        st = self.history.touch(src)
        st.events.append((now, pkt["dport"]))
        st.ports[pkt["dport"]] += 1
        # Each SYN enters and leaves the window once: O(1) amortised per packet.
        while st.events and now - st.events[0][0] > self.window:
            _, port = st.events.popleft()
            st.ports[port] -= 1
            if st.ports[port] == 0:
                del st.ports[port]
        if len(st.ports) > self.max_ports and now - st.last_alert > self.window:
            st.last_alert = now
            return {"type": "PORT_SCAN", "src": src,
                    "ports": len(st.ports), "window": self.window, "ts": now}
        return None

    def sweep(self, now):
        """Forget sources with nothing in the window and no recent alert."""
        self.history.drop_idle(lambda st: (not st.events or now - st.events[-1][0] > self.window)
                               and now - st.last_alert > self.window)


class _Buckets:
    """Time buckets of sets, with a running count of how many buckets hold
    each member, so the number of distinct members is O(1) to read."""
    __slots__ = ("buckets", "count", "last_alert")

    def __init__(self):
        self.buckets = {}         # bucket id -> set of members
        self.count = Counter()    # member -> number of buckets holding it
        self.last_alert = 0

    def add(self, bucket_id, member):
        s = self.buckets.setdefault(bucket_id, set())
        if member not in s:
            s.add(member)
            self.count[member] += 1

    def expire(self, oldest):
        for b in [b for b in self.buckets if b < oldest]:
            for member in self.buckets.pop(b):
                self.count[member] -= 1
                if self.count[member] == 0:
                    del self.count[member]

    def distinct(self):
        return len(self.count)


class SlowScanDetector:
    def __init__(self, max_ports=30, bucket_secs=60, n_buckets=10, max_keys=MAX_KEYS):
        self.max_ports = max_ports
        self.bucket_secs = bucket_secs
        self.n_buckets = n_buckets
        self.buckets = _LRU(_Buckets, max_keys)    # src -> ports per bucket

    def process(self, pkt):
        if not _is_syn(pkt):
            return None
        now = pkt["ts"]
        src = pkt["src"]
        bucket_id = int(now // self.bucket_secs)
        b = self.buckets.touch(src)
        b.add(bucket_id, pkt["dport"])
        b.expire(bucket_id - self.n_buckets + 1)
        window = self.bucket_secs * self.n_buckets
        ports = b.distinct()
        if ports > self.max_ports and now - b.last_alert > window:
            b.last_alert = now
            return {"type": "SLOW_PORT_SCAN", "src": src,
                    "ports": ports, "window": window, "ts": now}
        return None

    def sweep(self, now):
        window = self.bucket_secs * self.n_buckets
        oldest = int(now // self.bucket_secs) - self.n_buckets + 1
        for b in self.buckets.values():
            b.expire(oldest)
        self.buckets.drop_idle(lambda b: not b.buckets and now - b.last_alert > window)


class _DstState:
    __slots__ = ("srcs", "ports", "last_alert")

    def __init__(self):
        self.srcs = _Buckets()
        self.ports = _Buckets()
        self.last_alert = 0


class DistributedScanDetector:
    def __init__(self, min_sources=5, max_ports=30, bucket_secs=60, n_buckets=5,
                 max_keys=MAX_KEYS):
        self.min_sources = min_sources
        self.max_ports = max_ports
        self.bucket_secs = bucket_secs
        self.n_buckets = n_buckets
        self.buckets = _LRU(_DstState, max_keys)   # dst -> sources and ports per bucket

    def process(self, pkt):
        if not _is_syn(pkt):
            return None
        now = pkt["ts"]
        dst = pkt["dst"]
        bucket_id = int(now // self.bucket_secs)
        st = self.buckets.touch(dst)
        st.srcs.add(bucket_id, pkt["src"])
        st.ports.add(bucket_id, pkt["dport"])
        oldest = bucket_id - self.n_buckets + 1
        st.srcs.expire(oldest)
        st.ports.expire(oldest)
        window = self.bucket_secs * self.n_buckets
        n_srcs, n_ports = st.srcs.distinct(), st.ports.distinct()
        if n_srcs >= self.min_sources and n_ports > self.max_ports \
                and now - st.last_alert > window:
            st.last_alert = now
            return {"type": "DISTRIBUTED_SCAN", "dst": dst,
                    "sources": n_srcs, "ports": n_ports,
                    "window": window, "ts": now}
        return None

    def sweep(self, now):
        window = self.bucket_secs * self.n_buckets
        oldest = int(now // self.bucket_secs) - self.n_buckets + 1
        for st in self.buckets.values():
            st.srcs.expire(oldest)
            st.ports.expire(oldest)
        self.buckets.drop_idle(lambda st: not st.srcs.buckets and now - st.last_alert > window)


class FloodDetector:
    def __init__(self, per_src_limit=100, global_limit=500, host_limit=1000, window=5,
                 max_keys=MAX_KEYS):
        self.per_src_limit = per_src_limit
        self.global_limit = global_limit   # half-open to one service, all sources
        self.host_limit = host_limit       # half-open to one host, all sources and ports
        self.window = window
        self.max_keys = max_keys
        self.pending = OrderedDict()   # (src, sport, dst, dport) -> (time of SYN, SYN seq)
        self.per_src = Counter()       # (src, dst, dport) -> half-open count
        self.per_svc = Counter()       # (dst, dport)      -> half-open count
        self.per_host = Counter()      # dst               -> half-open count
        self.last_alert = OrderedDict()

    def _remove(self, key):
        del self.pending[key]
        src, sport, dst, dport = key
        for counter, k in ((self.per_src, (src, dst, dport)),
                           (self.per_svc, (dst, dport)),
                           (self.per_host, dst)):
            counter[k] -= 1
            if counter[k] == 0:
                del counter[k]

    def _alert(self, now, scope, key, alert):
        k = (scope, key)
        if now - self.last_alert.get(k, 0) > self.window:
            self.last_alert[k] = now
            self.last_alert.move_to_end(k)
            while len(self.last_alert) > self.max_keys:
                self.last_alert.popitem(last=False)
            return alert
        return None

    def sweep(self, now):
        for k in [k for k, t in self.last_alert.items() if now - t > self.window]:
            del self.last_alert[k]

    def process(self, pkt):
        if pkt["proto"] != "TCP":
            return None
        now = pkt["ts"]
        flags = pkt["flags"]

        # pending is in SYN arrival order, so expired entries are at the front;
        # at the cap the oldest is forgotten to make room for the next SYN.
        while self.pending:
            key, (ts, _) = next(iter(self.pending.items()))
            if now - ts <= self.window and len(self.pending) < self.max_keys:
                break
            self._remove(key)

        key = (pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"])

        if (flags & 0x12) == 0x02:                      # SYN only
            if key in self.pending:
                return None
            self.pending[key] = (now, pkt.get("seq"))
            src, sport, dst, dport = key
            self.per_src[(src, dst, dport)] += 1
            self.per_svc[(dst, dport)] += 1
            self.per_host[dst] += 1

            n = self.per_src[(src, dst, dport)]
            if n > self.per_src_limit:
                return self._alert(now, "src", (src, dst, dport), {
                    "type": "SYN_FLOOD", "src": src, "dst": dst, "dport": dport,
                    "half_open": n, "window": self.window, "ts": now})
            n = self.per_svc[(dst, dport)]
            if n > self.global_limit:
                return self._alert(now, "svc", (dst, dport), {
                    "type": "SYN_FLOOD", "src": "many", "dst": dst, "dport": dport,
                    "half_open": n, "window": self.window, "ts": now})
            n = self.per_host[dst]
            if n > self.host_limit:
                return self._alert(now, "host", dst, {
                    "type": "SYN_FLOOD", "src": "many", "dst": dst, "dport": "many",
                    "half_open": n, "window": self.window, "ts": now})
        elif (flags & 0x10) and not (flags & 0x02):     # ACK completes the handshake
            entry = self.pending.get(key)
            if entry is not None:
                _, syn_seq = entry
                # The client's final ACK carries ack = server ISN + 1, which we
                # cannot know, but its seq must be the SYN's seq + 1. An ACK that
                # does not continue the SYN is not a completed handshake.
                seq = pkt.get("seq")
                if syn_seq is None or seq is None or seq == (syn_seq + 1) & 0xFFFFFFFF:
                    self._remove(key)
        return None
