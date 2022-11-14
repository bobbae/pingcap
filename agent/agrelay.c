#ifndef __AGRELAY_C__
#define __AGRELAY_C__ 1
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

int my_idval[] = {		//XXX
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};


void
packet_handler(u_char * param, const struct pcap_pkthdr *header,
	       const u_char * pkt_data)
{
	u_char *message;
	int i;
	device_info_t *di = (device_info_t *) param;
	char buffer[MAXBUF];

	message = pkt_data + 14;
	if (pkt_data[12] != 0xda || pkt_data[13] != 0xda)
		return;

	int mlen = strlen(message);
	if (mlen < MINMSG || mlen >= MAXLINE) {

		printf("agrelay packet_handler, bad size %d\n", mlen);
		return;
	}
	printf("agrelay packet_handler received message %d, %s\n", mlen, message);

	message_t msg;
	if (parse_msg(message, &msg) < 0) {
		printf("can't parse msg\n");
		return;
	}
	char msgtype[MSLEN + 1];
	strcpy(msgtype, msg.type);
	if (msg_type_check(msgtype) < 0) {
		printf("invalid msg type %s\n", msgtype);
		return;
	}

	char plain_text[MSLEN + 1];
	memset((void *)plain_text, 0, sizeof(plain_text));

	crypto_ctx_t *cctx = get_my_cctx();

	uint8_t peer_public_key[KSLEN];
	fromhex((char *)peer_public_key, KSLEN, 16, (char *)msg.public_key);

	// presence of nonce or mac in the msg indicates encrypted content
	if (strlen(msg.nonce) > 0) {
		uint8_t mac[MAC_LEN];
		uint8_t nonce[NONCE_LEN];

        fromhex((char *)mac, MAC_LEN, 16,(char *) msg.mac);
        fromhex((char *)nonce, NONCE_LEN, 16, (char *)msg.nonce);

		uint8_t shared_secret[KSLEN];
        memset((void *)shared_secret, 0, sizeof(shared_secret));
		crypto_x25519(shared_secret, cctx->secret_key, peer_public_key);

		char cipher_text[MSLEN + 1];

		memset((void *)cipher_text, 0, sizeof(cipher_text));
		memset((void *)plain_text, 0, sizeof(plain_text));
		fromhex(cipher_text, MSLEN, 16, msg.cipher_text);

        uint8_t shared_secret_str[SLEN];
        memset((void *)shared_secret_str, 0, sizeof(shared_secret_str));
        tohex((char *)shared_secret, KSLEN, 16,(char *) shared_secret_str);
        printf("agrelay: decrypting with shared_secret %s peer_pub %s\n", shared_secret_str, msg.public_key);

		if (crypto_unlock
		    (plain_text, shared_secret, nonce, mac,
		     cipher_text, strlen(cipher_text))) {
			printf("agrelay error: cannot decrypt\n");
			return;
		}

		printf("agrelay decrypted: %s\n", plain_text);
	}

	char myaddr[MSLEN], srcaddr[MSLEN];
	sprintf(myaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
		di->macaddr[0],
		di->macaddr[1],
		di->macaddr[2], di->macaddr[3], di->macaddr[4], di->macaddr[5]);
	sprintf(srcaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
		pkt_data[6],
		pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10],
		pkt_data[11]);


	sprintf(buffer, get_relay_template(), "input", get_id_seq(), 
		myaddr, msg.public_key, srcaddr, "0xdada", plain_text, "");

	int n;
	n = sendto(di->sockfd, (const char *)buffer, strlen(buffer),
		   0, (const struct sockaddr *)&di->servaddr,
		   sizeof(di->servaddr));
	if (n < 0) {
		print_error("sendto failed");
		return;
	}
	printf("Relay forwarded %d bytes, %s\n", n, buffer);
}

int run_relay(int port, int devnum, char *address)
{
	int sockfd;
	struct hostent *he;
	struct sockaddr_in servaddr;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	pcap_if_t *adevs;
	adevs = init_alldevs();

	if (!adevs) {
		printf("cannot list network devices\n");
		return -1;
	}

	init_wsock();

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	//servaddr.sin_addr.s_addr = INADDR_ANY;
	if ((he = gethostbyname(address)) == NULL) {
		unsigned long ina = inet_addr(address);
		if (ina == -1) {
			print_error
			    ("gethostbyname failed and invalid IP address");
			return -2;
		}
		servaddr.sin_addr.s_addr = ina;
	} else {
		memcpy(&servaddr.sin_addr, he->h_addr_list[0], he->h_length);
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		return -3;
	}

	init_my_cctx(my_idval, sizeof(my_idval) / sizeof(int));

	if (get_num_devices() < 1) {
		printf("no network devices\n");
		return -4;
	}

	if (devnum < 0) {
		printf("Choose the network device from the list, use -d\n");
		printf("To list network devices use -l\n");
		return -5;
	}
	if (devnum >= get_num_devices()) {
		printf("network device index %d out of range\n", devnum);
		return -6;
	}

	pcap_if_t *d;
	int i;
	for (d = adevs, i = 0; i != devnum && d; d = d->next, i++) ;

	pcap_t *adh;
	adh = pcap_dev_setup(d);
	if (!adh) {
		printf("cannot setup pcap device %s\n", d->name);
		return -7;
	}
	unsigned char *macaddr = getmac(d->name);
	device_info_t di;
	di.d = d;
	di.macaddr = macaddr;
	di.sockfd = sockfd;
	di.servaddr = servaddr;
	pcap_loop(adh, 0, packet_handler, (unsigned char *)&di);
	// should not reach here

	//pcap_freealldevs(alldevs);
	//pcap_close(adhandle);
	return 0;
}

int print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h       print help\n");
	printf("-s       use socket\n");
	printf("-l       list network interfaces\n");
	printf("-d index specify network interface index\n");
	printf("-p port  specify port\n");
	printf("-a address specify name or address of server\n");
	fflush(stdout);
}

#ifndef CGO
int main(int argc, char *argv[])
{
	int c;
	int port = PORT, list_ifs = 0;
	int devnum = -1;
	char *address = 0;

	opterr = 0;
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	while ((c = getopt(argc, argv, "hslp:d:a:")) != -1) {
		switch (c) {
		case 'h':
			print_help(argv[0]);
			fexit(0);
		case 'a':
			address = optarg;
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

	if (list_ifs) {
		show_devs();
		return 0;
	}

	run_relay(port, devnum, address);
	return 0;
}
#endif
#endif
