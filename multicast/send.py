# SENDER

import socket

group = '224.1.1.1'
port = 5004
MCAST_IF_IP = "172.18.96.60"


# 2-hop restriction in network
ttl = 2

sock = socket.socket(socket.AF_INET,
                     socket.SOCK_DGRAM,
                     socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP,
                socket.IP_MULTICAST_TTL,
                ttl)

sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(MCAST_IF_IP))

sock.sendto(b"hello world", (group, port))
