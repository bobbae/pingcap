#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <mqtt.h>

#ifdef WIN32
#include <ws2tcpip.h>
#endif
#ifdef LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#endif

struct mqtt_client client;

void publish_callback(void **unused, struct mqtt_response_publish *published);

int main(int argc, const char *argv[])
{
	const char *addr;
	const char *port;
	const char *topic;

	if (argc > 1) {
		addr = argv[1];
	} else {
		addr = "test.mosquitto.org";
	}

	if (argc > 2) {
		port = argv[2];
	} else {
		port = "1883";
	}
	int portnum = atoi(port);

	if (argc > 3) {
		topic = argv[3];
	} else {
		topic = "datetime";
	}

	printf("Usage: %s addr port topic\n", argv[0]);
	printf("default addr test.mosquitto.org\n");
	printf("default port 1883\n");
	printf("default topic datetime\n");

	printf
	    ("Will connect to MQTT broker at addr %s at port %s on topic %s\n",
	     addr, port, topic);

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

#ifdef WIN32
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) {
		printf("WSAStartup failed\n");
		exit(1);
	}
#endif

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
		perror("Failed to open socket: ");
		exit(1);
	}
	struct hostent *host;
	struct sockaddr_in sin;
	host = gethostbyname(addr);
	if (!host) {
		perror("error: can't gethostbyname");
		exit(1);
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(portnum);
	sin.sin_addr.s_addr = *(long *)(host->h_addr_list[0]);
	printf("%s\n", inet_ntoa(sin.sin_addr));

	if (connect(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
		close(sockfd);
		perror("error: can't connect");
		exit(1);
	}
#ifdef WIN32
	int on = 1;
	ioctlsocket(sockfd, FIONBIO, &on);
#endif
#ifdef LINUX
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
#endif

	uint8_t sendbuf[2048];
	uint8_t recvbuf[1024];
	mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf,
		  sizeof(recvbuf), publish_callback);
	const char *client_id = NULL;
	uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
	mqtt_connect(&client, client_id, NULL, NULL, 0, NULL, NULL,
		     connect_flags, 400);

	if (client.error != MQTT_OK) {
		fprintf(stderr, "error: %s\n", mqtt_error_str(client.error));
		exit(1);
	}
	char hostname[200];
	gethostname(hostname, sizeof(hostname));
	mqtt_subscribe(&client, topic, 0);
	printf("%s is ready to begin publishing the time.\n", argv[0]);
	for (;;) {
		time_t timer;
		time(&timer);
		struct tm *tm_info = localtime(&timer);
		char timebuf[26];
		strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

		char application_message[256];
		snprintf(application_message, sizeof(application_message),
			 "%s: The time is %s", hostname, timebuf);
		printf("%s published : \"%s\"", argv[0], application_message);

		mqtt_publish(&client, topic, application_message,
			     strlen(application_message) + 1,
			     MQTT_PUBLISH_QOS_0);

		if (client.error != MQTT_OK) {
			fprintf(stderr, "error: %s\n",
				mqtt_error_str(client.error));
			exit(1);
		}
		mqtt_sync(&client);
		sleep(5);
	}

	mqtt_sync(&client);

	printf("\n%s disconnecting from %s\n", argv[0], addr);
	sleep(1);

	exit(0);
}

void publish_callback(void **unused, struct mqtt_response_publish *published)
{
	/* note that published->topic_name is NOT null-terminated */
	char *topic_name = (char *)malloc(published->topic_name_size + 1);
	memcpy(topic_name, published->topic_name, published->topic_name_size);
	topic_name[published->topic_name_size] = '\0';

	printf("\nReceived publish('%s'): %s\n", topic_name,
	       (const char *)published->application_message);

	free(topic_name);
}
