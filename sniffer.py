import socket
import struct

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    data, addr = s.recvfrom(65535)
    dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
    if eth_type != 0x0800:
        continue
    ver_ihl, tos, total_len, ident, frag, ttl, proto, csum, src_ip, dst_ip = \
        struct.unpack("!BBHHHBBH4s4s", data[14:34])
    ihl = (ver_ihl & 0x0F) * 4
    print(socket.inet_ntoa(src_ip), "->", socket.inet_ntoa(dst_ip),
          "proto", proto, "ttl", ttl, "ihl", ihl, "total_len", total_len)
