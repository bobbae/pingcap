#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include "common.h"

int main()
{
	int sockfd;
	char buffer[MAXLINE];
	char *hello = "Hello from server";
	struct sockaddr_in servaddr, cliaddr;

#ifdef _WIN32
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) {
		print_error("WSAStartup failed");
		exit(3);
	}
#endif

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		exit(4);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	// Bind the socket with the server address
	if (bind(sockfd, (const struct sockaddr *)&servaddr,
		 sizeof(servaddr)) < 0) {
		print_error("bind failed");
		exit(5);
	}

	int len, n;

	len = sizeof(cliaddr);

	n = recvfrom(sockfd, (char *)buffer, MAXLINE,
		     0, (struct sockaddr *)&cliaddr, &len);
	if (n < 0) {
		print_error("recvfrom failed");
		exit(9);
	}
	buffer[n] = '\0';
	printf("Client sent: n %d buffer %s\n", n, buffer);
	n = sendto(sockfd, (const char *)hello, strlen(hello),
		   0, (const struct sockaddr *)&cliaddr, len);
	if (n < 0) {
		print_error("sendto failed");
		exit(10);
	}
	printf("Hello message sent.\n");

	return 0;
}
