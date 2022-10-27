#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MSGBUFSIZE 256

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("port required\n");
		return 1;
	}

	int port = atoi(argv[1]);

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(0x0101, &wsaData)) {
		perror("WSAStartup");
		return 1;
	}
#endif

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	u_int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)
	    ) < 0) {
		perror("Reusing ADDR failed");
		return 1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	while (1) {
		char msgbuf[MSGBUFSIZE];
		int addrlen = sizeof(addr);
		printf("receiving\n");
		int nbytes = recvfrom(fd,
				      msgbuf,
				      MSGBUFSIZE,
				      0,
				      (struct sockaddr *)&addr,
				      &addrlen);
		if (nbytes < 0) {
			perror("recvfrom");
			return 1;
		}
		msgbuf[nbytes] = '\0';
		printf("received %s\n", msgbuf);
	}

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
