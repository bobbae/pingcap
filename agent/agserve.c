#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>

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

int my_idval[] = {	//XXX
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};


int msg_type_check(char *msgtype)
{
	char *valid_msgtypes[] = { "hello" };

	int i;
	for (i = 0; i < sizeof(valid_msgtypes) / sizeof(char *); i++) {
		if (strcmp(valid_msgtypes[i], msgtype) == 0)
			return 1;
	}
	return 0;
}

char *fill_response(char *buffer, char *peer_pub, char *msgtype,
		    char *plain_text, char *extra)
{
	char cipher_text[MSLEN + 1], cipher_text_str[MSLEN + 1];
	uint8_t peer_public_key[KSLEN];

	crypto_ctx_t *cctx = get_my_cctx();
	fill_str(cctx);

	fromhex(peer_public_key, KSLEN, 16, peer_pub);

	crypto_x25519(cctx->shared_secret, cctx->secret_key,
		      peer_public_key);

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)cipher_text_str, 0, sizeof(cipher_text_str));

	crypto_lock(cctx->mac, cipher_text, cctx->shared_secret,
		    cctx->nonce, plain_text, strlen(plain_text));
	printf("plain_text %d %s\n", (int)strlen(plain_text), plain_text);

	tohex(cipher_text, strlen(plain_text), 16, cipher_text_str);
	printf("cipher_text_str %d %s\n",(int) strlen(cipher_text_str), cipher_text_str);

	// XXX params: unique_id, signature, signature_public_key, public_key, mac, nonce, cipher_text, empty
	sprintf(buffer, (char *)get_msg_template(), msgtype, get_id_seq(),
		cctx->unique_id_str, cctx->signature_str, cctx->signature_public_key_str,
		cctx->public_key_str, cctx->mac_str, cctx->nonce_str, cipher_text_str, extra);
	printf("buffer %s\n", buffer);
}



int handle_msg(char *buffer)
{
	message_t msg;
	char msgtype[MSLEN + 1];

	if (parse_msg(buffer, &msg) < 0) {
		printf("cannot parse message\n");
		return -3;
	}

	strcpy(msgtype, msg.type);

	if (msg_type_check(msgtype) < 0) {
		printf("invalid msg type %s\n", msgtype);
		return -5;
	}

	if (verify_signature(&msg) < 0) {
		printf("cannot verify signature\n");
		return -4;
	}

	strcat(msgtype, "resp");
	fill_response(buffer, msg.params[3], msgtype,
		      "secret config content 1 2 3", "extra plain text msg");

	return 1;
}

int proc_sock(int port)
{
	int sockfd, n, salen;
	struct sockaddr_in servaddr;
	char buffer[MAXLINE];

	init_wsock();

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = INADDR_ANY;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		return -2;
	}
	if (bind(sockfd, (const struct sockaddr *)&servaddr,
		 sizeof(servaddr)) < 0) {
		print_error("bind failed");
		return -3;
	}

	for (;;) {
		salen = sizeof(servaddr);
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, 0,
			     (struct sockaddr *)&servaddr, &salen);
		if (n < 0) {
			print_error("recvfrom failed");
			return -4;
		}
		buffer[n] = '\0';
		printf("Received %d bytes, %s\n", n, buffer);

		if (handle_msg(buffer) < 0) {
			printf("error handling message\n");
			return -9;
		}
		printf("sending %s\n", buffer);
		n = sendto(sockfd, (const char *)buffer, strlen(buffer),
			   0, (const struct sockaddr *)&servaddr,
			   sizeof(servaddr));
		if (n < 0) {
			print_error("sendto failed");
			fexit(1);
		}
		printf("Sent %d bytes, %s\n", n, buffer);
	}
	close(sockfd);
	return 1;
}

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data)
{
	const u_char *message;
	u_char *pktbuf, packet[1500];
	int i;
	device_info_t *di = (device_info_t *) param;

	message = pkt_data + 14;
	if (pkt_data[12] != 0xda || pkt_data[13] != 0xda) 
		return;
	printf("Got 0xdada len %d message %s\n",(int) strlen(message), message);

	if (strlen(message) < MINMSG || strlen(message) >= MAXLINE) {
		printf("bad size\n");
		return;
	}
	memset((void *)packet, 0, sizeof(packet));
	pktbuf = packet + 14;
	strcpy(pktbuf, message);
	if (handle_msg(pktbuf) < 0) {
		printf("failed to handle msg\n");
		return;
	}

	fill_ether_header((char *)packet,(char *) di->macaddr,(char *) &pkt_data[6]);

	printf("sending pktbuf %s\n", pktbuf);
	if (pcap_sendpacket(get_adhandle(), packet, strlen(pktbuf) + 14) != 0) {
		printf("error sending the packet\n");
		return;
	}
}

int print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h       print help\n");
	printf("-s       use socket\n");
	printf("-l       list network interfaces\n");
	printf("-d index specify network interface index\n");
	printf("-p port  specify port\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int c;
	int use_sock = 0, port = PORT, list_ifs = 0;
	int devnum = -1;

	opterr = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	while ((c = getopt(argc, argv, "hslp:d:")) != -1) {
		switch (c) {
		case 'h':
			print_help(argv[0]);
			fexit(0);
		case 's':
			use_sock = 1;
			break;
		case 'l':
			list_ifs = 1;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'd':
			devnum = atoi(optarg);
			break;
		case '?':
			if (optopt == 'p' || optopt == 'd')
				fprintf(stderr,
					"Option %c requires an argument.\n",
					optopt);
			else if (isprint(optopt))
				fprintf(stderr, "unknown option -%c.\n",
					optopt);
			else
				fprintf(stderr,
					"unknown option character %c.\n",
					optopt);
			fexit(1);
		default:
			fprintf(stderr, "unknown option %c.\n", c);
			fexit(1);
		}
	}
	init_my_cctx(my_idval, sizeof(my_idval) / sizeof(int));

	if (use_sock) {
		if (list_ifs) {
			printf("ignoring -l\n");
		}
		if (proc_sock(port) < 0) {
			printf("error processing socket\n");
			fexit(1);
		}
	} else {
		pcap_if_t *adevs;
		adevs = init_alldevs();
		if (!adevs) {
			printf("cannot list network devices\n");
			fexit(1);
		}
		if (get_num_devices() < 1) {
			printf("no network devices\n");
			fexit(1);
		}
		if (list_ifs) {
			list_devs(adevs);
			return 0;
		}
		if (devnum < 0) {
			printf
			    ("Choose the network device from the list, use -d\n");
			printf("To list network devices use -l\n");
			fexit(1);
		}
		if (devnum >= get_num_devices()) {
			printf("network device index %d out of range\n",
			       devnum);
			fexit(1);
		}

		pcap_if_t *d;
		int i;
		for (d = adevs, i = 0; i != devnum && d; d = d->next, i++) ;

		pcap_t *adh;
		adh = pcap_dev_setup(d);
		if (!adh) {
			printf("cannot setup pcap device %s\n", d->name);
			fexit(1);
		}
		unsigned char *macaddr = getmac(d->name);
		device_info_t di;
		di.d = d;
		di.macaddr = macaddr;
		pcap_loop(adh, 0, packet_handler, (unsigned char *)&di);

		//pcap_freealldevs(alldevs);
		//pcap_close(adhandle);
	}
	return 0;
}
