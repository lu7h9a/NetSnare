import json
import os
import pwd
import socket
import struct
import time
from collections import deque

from detect import ScanDetector, SlowScanDetector, DistributedScanDetector, FloodDetector

# Everything the dashboard server may serve lives in www/; the packet log
# lives in logs/ (owner-only), never under the served directory.
WWW_DIR = "www"
LOG_DIR = "logs"
ALERTS_FILE = os.path.join(WWW_DIR, "alerts.json")
PACKETS_FILE = os.path.join(LOG_DIR, "packets.jsonl")
PACKETS_MAX_BYTES = 100 * 1024 * 1024    # rotate to packets.jsonl.1 beyond this
SWEEP_SECS = 5

FLAG_BITS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
             ("PSH", 0x08), ("ACK", 0x10)]


def parse_packet(data, ts=None):
    """Turn raw bytes into a dict, or None if not IPv4 TCP/UDP.

    IP fragments return {"proto": "FRAG", ...}: a non-first fragment holds no
    transport header, and decoding its payload as one would let an attacker
    forge any TCP flags and ports. Fragments are counted, not reassembled.
    """
    if len(data) < 34:
        return None
    eth_type = struct.unpack("!H", data[12:14])[0]
    if eth_type != 0x0800:
        return None

    ver_ihl, tos, total_len, ident, frag, ttl, proto, csum, src_ip, dst_ip = \
        struct.unpack("!BBHHHBBH4s4s", data[14:34])
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or total_len < ihl:
        return None
    # Trust neither Ethernet padding nor a total length beyond what arrived.
    end = min(len(data), 14 + total_len)
    start = 14 + ihl

    pkt = {"ts": time.time() if ts is None else ts, "src": socket.inet_ntoa(src_ip),
           "dst": socket.inet_ntoa(dst_ip), "ttl": ttl, "len": len(data)}

    frag_offset = frag & 0x1FFF
    more_fragments = frag & 0x2000
    if frag_offset or more_fragments:
        pkt.update(proto="FRAG", ip_proto=proto, frag_offset=frag_offset * 8)
        return pkt

    if proto == 6:
        if end < start + 20:
            return None
        sport, dport, seq, ack, off, flags, win, tcsum, urg = \
            struct.unpack("!HHIIBBHHH", data[start:start + 20])
        if (off >> 4) < 5:
            return None
        names = ",".join(n for n, bit in FLAG_BITS if flags & bit)
        pkt.update(proto="TCP", sport=sport, dport=dport, seq=seq, ack=ack,
                   flags=flags, flag_names=names)
    elif proto == 17:
        if end < start + 8:
            return None
        sport, dport, length, ucsum = struct.unpack("!HHHH", data[start:start + 8])
        pkt.update(proto="UDP", sport=sport, dport=dport)
    else:
        return None
    return pkt


def write_state(alerts, stats):
    tmp = f"{ALERTS_FILE}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"alerts": list(alerts), "stats": stats}, f)
        os.replace(tmp, ALERTS_FILE)
    except OSError as e:   # a full disk must not stop detection
        print("WARNING could not write", ALERTS_FILE, e)
        try:
            os.unlink(tmp)
        except OSError:
            pass


def drop_privileges():
    """Prepare www/ and logs/ for the unprivileged user, then become it.

    Runs as the user who called sudo, or as nobody. The raw socket stays
    open; nothing that parses packets keeps root.
    """
    if os.geteuid() != 0:
        return
    name = os.environ.get("SUDO_USER") or "nobody"
    if name == "root":
        name = "nobody"
    pw = pwd.getpwnam(name)
    for d, mode in ((WWW_DIR, 0o755), (LOG_DIR, 0o700)):
        os.makedirs(d, exist_ok=True)
        os.chown(d, pw.pw_uid, pw.pw_gid)
        os.chmod(d, mode)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


class PacketLog:
    """packets.jsonl, owner-only, rotated once it reaches PACKETS_MAX_BYTES."""

    def __init__(self, path=PACKETS_FILE, max_bytes=PACKETS_MAX_BYTES):
        self.path, self.max_bytes = path, max_bytes
        self.f = self._open()

    def _open(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        return os.fdopen(fd, "a")

    def write(self, pkt):
        try:
            self.f.write(json.dumps(pkt) + "\n")
            self.f.flush()
            if self.f.tell() >= self.max_bytes:
                self.f.close()
                os.replace(self.path, self.path + ".1")
                self.f = self._open()
        except OSError as e:
            print("WARNING packet log:", e)


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    drop_privileges()
    os.umask(0o022)
    detectors = [ScanDetector(), SlowScanDetector(),
                 DistributedScanDetector(), FloodDetector()]
    alerts = deque(maxlen=200)
    stats = {"TCP": 0, "UDP": 0, "FRAG": 0}
    last_write = last_sweep = 0
    write_state(alerts, stats)
    log = PacketLog()

    while True:
        data, addr = s.recvfrom(65535)
        if addr[2] == socket.PACKET_OUTGOING and addr[0] == "lo":
            continue   # on loopback every packet is seen twice; keep one copy
        pkt = parse_packet(data)
        if pkt is None:
            continue
        log.write(pkt)
        stats[pkt["proto"]] += 1
        now = pkt["ts"]

        changed = False
        if pkt["proto"] != "FRAG":
            for d in detectors:
                alert = d.process(pkt)
                if alert:
                    alerts.append(alert)
                    print("ALERT", alert)
                    changed = True

        if now - last_sweep > SWEEP_SECS:
            for d in detectors:
                d.sweep(now)
            last_sweep = now
        if changed or now - last_write > 2:
            write_state(alerts, stats)
            last_write = now


if __name__ == "__main__":
    main()
