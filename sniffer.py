import socket
import struct

FLAG_BITS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
             ("PSH", 0x08), ("ACK", 0x10)]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    data, addr = s.recvfrom(65535)
    dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
    if eth_type != 0x0800:
        continue
    ver_ihl, tos, total_len, ident, frag, ttl, proto, csum, src_ip, dst_ip = \
        struct.unpack("!BBHHHBBH4s4s", data[14:34])
    ihl = (ver_ihl & 0x0F) * 4
    start = 14 + ihl
    sip = socket.inet_ntoa(src_ip)
    dip = socket.inet_ntoa(dst_ip)

    if proto == 6:
        sport, dport, seq, ack, off, flags, win, tcsum, urg = \
            struct.unpack("!HHIIBBHHH", data[start:start + 20])
        names = ",".join(n for n, bit in FLAG_BITS if flags & bit)
        print(f"TCP {sip}:{sport} -> {dip}:{dport} [{names}] seq={seq} ack={ack}")
    elif proto == 17:
        sport, dport, length, ucsum = struct.unpack("!HHHH", data[start:start + 8])
        print(f"UDP {sip}:{sport} -> {dip}:{dport} len={length}")
