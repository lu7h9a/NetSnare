import socket

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
data,addr = s.recvfrom(65535)
print("interface:",addr[0])
print("length:   ", len(data))
print("first 14: ", data[:14].hex(" "))

