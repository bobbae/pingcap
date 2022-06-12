import sys
import socket

ETH_P_ALL=3 # not defined in socket module, sadly...
s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.bind((sys.argv[1], 0))
r=s.recv(2000)
sys.stdout.write("<%s>\n"%repr(r))
