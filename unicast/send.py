import sys
import socket

def sendudp(ipaddr, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.sendto(bytes(message, "utf-8"), (ipaddr, port))

def main():
    ipaddr = sys.argv[1]
    port = sys.argv[2]
    message = sys.argv[3]
    print("sending", ipaddr, port, message)
    sendudp(ipaddr, int(port), message)

if __name__ == "__main__":
    main()
