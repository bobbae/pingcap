#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#endif

#include "getopt.h"
#include "pcap.h"
#include "monocypher.h"
#include "common.h"

int main()
{
	char macaddr[7];

	memset((void *)macaddr, 0, sizeof(macaddr));
	sscanf("22:33:44:55:66:ff", "%02x:%02x:%02x:%02x:%02x:%02x",
	       &macaddr[0],
	       &macaddr[1], &macaddr[2], &macaddr[3], &macaddr[4], &macaddr[5]);

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       macaddr[0] & 0xff,
	       macaddr[1] & 0xff,
	       macaddr[2] & 0xff,
	       macaddr[3] & 0xff, macaddr[4] & 0xff, macaddr[5] & 0xff);

	char *msgtype = "hello";

	if (startswith(msgtype, "hel")) {
		printf("%s starts with hel\n", msgtype);
	}
	if (endswith(msgtype, "-enc")) {
		printf("%s endswith -enc\n", msgtype);
	}
	msgtype = "hello-resp-enc";
	if (endswith(msgtype, "-enc")) {
		printf("%s endswith -enc\n", msgtype);
	}	
}
