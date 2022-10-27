#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf
		    ("Command line args should be multicast group and port\n");
		printf("(e.g. for SSDP, `sender 239.255.255.250 1900`)\n");
		return 1;
	}

	char *group = argv[1];
	int port = atoi(argv[2]);

	const int delay_secs = 1;
	const char *message = "Hello, World!";

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

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(group);
	addr.sin_port = htons(port);

	while (1) {
		char ch = 0;
		int nbytes = sendto(fd,
				    message,
				    strlen(message),
				    0,
				    (struct sockaddr *)&addr,
				    sizeof(addr)
		    );
		if (nbytes < 0) {
			perror("sendto");
			return 1;
		}
		printf("sent\n");

#ifdef _WIN32
		Sleep(delay_secs * 1000);
#else
		sleep(delay_secs);
#endif
	}

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
