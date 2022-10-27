#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include "common.h"

int main(int argc, char *argv[])
{
	int sockfd;
	char buffer[MAXLINE];
	char *hello = "Hello from client";
	struct sockaddr_in servaddr;
	struct hostent *he;

#ifdef _WIN32
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) {
		print_error("WSAStartup failed");
		exit(3);
	}
#endif

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	//servaddr.sin_addr.s_addr = INADDR_ANY;

	if (argc < 2) {
		printf("Usage: %s hostname\nhostname required\n", argv[0]);
		exit(1);
	}

	char *hostname = argv[1];

	if ((he = gethostbyname(hostname)) == NULL) {
		unsigned long ina = inet_addr(hostname);
		if (ina == -1) {
			print_error
			    ("gethostbyname failed and invalid IP address");
			exit(7);
		}
		servaddr.sin_addr.s_addr = ina;
	} else {
		memcpy(&servaddr.sin_addr, he->h_addr_list[0], he->h_length);

	}
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		exit(3);
	}

	int n, len;

	n = sendto(sockfd, (const char *)hello, strlen(hello),
		   0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	if (n < 0) {
		print_error("sendto failed");
		exit(5);
	}
	printf("Hello message sent %d bytes.\n", n);

	len = sizeof(servaddr);
	n = recvfrom(sockfd, (char *)buffer, MAXLINE,
		     0, (struct sockaddr *)&servaddr, &len);
	if (n < 0) {
		print_error("recvfrom failed");
		exit(6);
	}
	buffer[n] = '\0';
	printf("Server sent: %s\n", buffer);

	close(sockfd);
	return 0;
}
