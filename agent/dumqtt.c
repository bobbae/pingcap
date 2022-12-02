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

void print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h print help\n");
	printf("-a address   specify IP address of the server (test.mosquitto.org)\n");
	printf("-p port      specify port of the server (1883)\n");
	printf("-t topic     specify topic (datetime)\n");
	printf("-m message   message to send (hello)\n");
	printf("-d delay     specify delay in seconds between messages (0)\n");
	printf("-l           continuous loop\n");
	
	fflush(stdout);
	exit(1);
}

int main(int argc, const char *argv[])
{
	char *message = "hello";
	char *topic ="datetime";
	int loopit = 0;
	int delay = 0;

	int i = 1;
	int port = 1883;
	char *address =  "test.mosquitto.org";

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);


	while (i < argc) {
		if (strcmp(argv[i], "-h") == 0) {
			print_help(argv[0]);
		} else if (strcmp(argv[i], "-l") == 0) {
			loopit = 1;
		} else if (strcmp(argv[i], "-m") == 0) {
			if (++i < argc)
				message = argv[i];
			else
				print_help(argv[0]);
		} else if (strcmp(argv[i], "-d") == 0) {
			if (++i < argc)
				delay = atoi(argv[i]);
			else
				print_help(argv[0]);
		} else if (strcmp(argv[i], "-a") == 0) {
			if (++i < argc)
				address = argv[i];
			else
				print_help(argv[0]);
		} else if (strcmp(argv[i], "-t") == 0) {
			if (++i < argc)
				topic = argv[i];
			else
				print_help(argv[0]);
		} else {
			print_help(argv[0]);
		}
		i++;
	}

	
	printf
	    ("Will connect to MQTT broker at addr %s at port %d on topic %s\n",
	     address, port, topic);


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
	host = gethostbyname(address);
	if (!host) {
		perror("error: can't gethostbyname");
		exit(1);
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
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
	printf("subscribed to the topic %s\n", topic);
	do {
		mqtt_publish(&client, topic, message,
			     strlen(message) + 1,
			     MQTT_PUBLISH_QOS_0);

		if (client.error != MQTT_OK) {
			fprintf(stderr, "error: %s\n",
				mqtt_error_str(client.error));
			exit(1);
		}
		mqtt_sync(&client);
		sleep(delay);
	} while (loopit);

	mqtt_sync(&client);

	printf("\n%s disconnecting from %s\n", argv[0], address);
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
