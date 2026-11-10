import json
import socket
import struct
import time
import os 

from detect import(ScanDetector, SlowScanDetector, DistributedScanDetector, FloodDetector)

ALERTS_FILE="alerts.json"

FLAG_BITS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
             ("PSH", 0x08), ("ACK", 0x10)]


def parse_packet(data):
    """Turn raw bytes into a dict, or None if not IPv4 TCP/UDP."""
    if len(data) < 34:
        return None
    eth_type = struct.unpack("!H", data[12:14])[0]
    if eth_type != 0x0800:
        return None

    ver_ihl, tos, total_len, ident, frag, ttl, proto, csum, src_ip, dst_ip = \
        struct.unpack("!BBHHHBBH4s4s", data[14:34])
    ihl = (ver_ihl & 0x0F) * 4
    start = 14 + ihl

    pkt = {"ts": time.time(), "src": socket.inet_ntoa(src_ip),
           "dst": socket.inet_ntoa(dst_ip), "ttl": ttl, "len": len(data)}

    if proto == 6:
        if len(data) < start + 20:
            return None
        sport, dport, seq, ack, off, flags, win, tcsum, urg = \
            struct.unpack("!HHIIBBHHH", data[start:start + 20])
        names = ",".join(n for n, bit in FLAG_BITS if flags & bit)
        pkt.update(proto="TCP", sport=sport, dport=dport, seq=seq, ack=ack,
                   flags=flags, flag_names=names)
    elif proto == 17:
        if len(data) < start + 8:
            return None
        sport, dport, length, ucsum = struct.unpack("!HHHH", data[start:start + 8])
        pkt.update(proto="UDP", sport=sport, dport=dport)
    else:
        return None
    return pkt
def write_state(alerts, stats):
    tmp = f"{ALERTS_FILE}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump({"alerts": alerts[-200:], "stats": stats}, f)
    os.replace(tmp, ALERTS_FILE)


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    detectors = [ScanDetector(), SlowScanDetector(),
                 DistributedScanDetector(), FloodDetector()]
    alerts = []
    stats = {"TCP": 0, "UDP": 0}
    last_write = 0
    write_state(alerts, stats)

    with open("packets.jsonl", "a") as f:
        while True:
            data, addr = s.recvfrom(65535)
            pkt = parse_packet(data)
            if pkt is None:
                continue
            f.write(json.dumps(pkt) + "\n")
            f.flush()
            stats[pkt["proto"]] += 1

            changed = False
            for d in detectors:
                alert = d.process(pkt)
                if alert:
                    alerts.append(alert)
                    print("ALERT", alert)
                    changed = True

            if changed or pkt["ts"] - last_write > 2:
                write_state(alerts, stats)
                last_write = pkt["ts"]
if __name__ == "__main__":
    main()
