import socket
import struct

def mac(b):
    return ":".join(f"{x:02x}" for x in b)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    data, addr = s.recvfrom(65535)
    dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
    print(mac(dst), "<-", mac(src), hex(eth_type), len(data))
