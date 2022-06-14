import sys
import socket

ipaddr = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = (ipaddr, port)
s.bind(server_addr)

print("server running at", server_addr)

while True:
    data, addr = s.recvfrom(4000)
    print("receieved", data, "from", addr)

