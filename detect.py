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
