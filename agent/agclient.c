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
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0
};

void fill_hello(char *buffer)
{
	crypto_ctx_t *cctx = get_my_cctx();
	fill_str(cctx);

	/* printf("uniq id %s signature %s signature public key %s public key %s\n", 
	   unique_id_str, signature_str, signature_public_key_str, public_key_str);
	 */

	sprintf(buffer, (char *)get_msg_template(), "hello", get_id_seq(),
		cctx->unique_id_str, cctx->signature_str,
		cctx->signature_public_key_str, cctx->public_key_str, "", "",
		"", "");
}

int handle_command(char *packet, char *peer_public_key, char *cmd)
{
    printf("handle_command %s\n", cmd);
	if (strncmp(cmd, "send", 4) == 0){
		char *param = cmd + 5;
		if (strncmp(param, "info", 4) == 0) {
			char *msgtype = "info";
			char *extra = "extra info";
			char *plain_text = "some info";
			
            printf("calling encrypt_send_packet msgtype %s plain_text %s\n",
                    msgtype, plain_text);
			return encrypt_send_packet(packet, peer_public_key,
						   msgtype, plain_text, extra);
		}
	} 
	printf("unknown cmd %s\n", cmd);
	return -1;
}

int handle_msg(char *packet, device_info_t *di )
{
	message_t msg;
	char msgtype[MSLEN + 1];

	if (parse_msg(packet+14, &msg) < 0) {
		printf("cannot parse message\n");
		return -3;
	}
	strcpy(msgtype, (const char *)msg.type);

	if (msg_type_check(msgtype) < 0) {
		printf("invalid msg type %s\n", msgtype);
		return -5;
	}

	crypto_ctx_t *cctx = get_my_cctx();

	uint8_t peer_public_key[KSLEN];
	uint8_t mac[MAC_LEN];
	uint8_t nonce[NONCE_LEN];

	fromhex((char *)peer_public_key, KSLEN, 16, (char *)msg.public_key);
	fromhex((char *)mac, MAC_LEN, 16,(char *) msg.mac);
	fromhex((char *)nonce, NONCE_LEN, 16, (char *)msg.nonce);

	uint8_t shared_secret[KSLEN];
	memset((void *)shared_secret, 0, sizeof(shared_secret));
	crypto_x25519(shared_secret, cctx->secret_key, peer_public_key);

	uint8_t shared_secret_str[SLEN];
	memset((void *)shared_secret_str, 0, sizeof(shared_secret_str));
	tohex((char *)shared_secret, KSLEN, 16,(char *) shared_secret_str);

	printf("agclient: decrypting with shared_secret %s peer_pub %s\n", shared_secret_str, msg.public_key);
	
	char cipher_text[MSLEN + 1], plain_text[MSLEN + 1];

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)plain_text, 0, sizeof(plain_text));
	fromhex((char *)cipher_text, MSLEN, 16, (char *)msg.cipher_text);

	if (crypto_unlock
	    ((uint8_t *)plain_text, shared_secret, nonce, mac,
	     (uint8_t *)cipher_text, strlen(cipher_text))) {
		printf("agclient error: cannot decrypt\n");
		return -9;
	}
	printf("agclient decrypted: %s\n", plain_text);

	fill_ether_header((char *)packet, (unsigned char *)di->macaddr,
			  (unsigned char *)&packet[6]);
	
	handle_command(packet, (char *) msg.public_key, plain_text);
	return 1;
}

char *get_bogus_mac()
{
	static char dstaddr[6];
	dstaddr[0] = 0x00;
	dstaddr[1] = 0x60;
	dstaddr[2] = 0xe9;
	dstaddr[3] = 0x0a;
	dstaddr[4] = 0x0b;
	dstaddr[5] = 0x0c;
	return dstaddr;
}

int send_hello_packet(char *packet, char *macaddr, char *src)
{
	fill_ether_header(packet, (unsigned char *)macaddr, (unsigned char *) src);
	fill_hello(packet + 14);

	if (pcap_sendpacket(get_adhandle(), (const u_char *)packet, 14 + strlen(packet + 14)) !=
	    0) {
		printf("error sending the packet\n");
		return -1;
	}
	printf("sent %d, %s\n", strlen(packet + 14) + 14, packet + 14);
	return 1;
}

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data)
{
	const u_char *message;
	u_char packet[1500];
	int i;
	device_info_t *di = (device_info_t *) param;

	message = pkt_data + 14;
	if (pkt_data[12] != 0xda || pkt_data[13] != 0xda)
		return;
	int mlen = strlen((const char *)message);
	if (mlen < MINMSG || mlen >= MAXLINE) {
		printf("agclient bad size %d\n", mlen);
		return;
	}
	memset((void *)packet, 0, sizeof(packet));
	strcpy((char *)(packet+14), (const char *)message);
	if (handle_msg((char *)packet, di) < 0) {
		printf("failed to handle msg\n");
		return;
	}
}

void print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h print help\n");
	printf("-s use socket\n");
	printf("-l list network interfaces\n");
	printf("-d index specify network interface index\n");
	printf("-p port specify port\n");
	printf("-a address specify name or address of server\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int port;
	char *address = 0;
	int c;
	int list_ifs = 0;
	int devnum = -1;

	opterr = 0;
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	port = PORT;

	while ((c = getopt(argc, argv, "hslp:a:d:")) != -1) {
		switch (c) {
		case 'h':
			print_help(argv[0]);
			fexit(0);
		case 'l':
			list_ifs = 1;
			break;
		case 'a':
			address = optarg;
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

	char packet[1500];
	unsigned char *macaddr = (unsigned char *) getmac(d->name);
	memset((void *)packet, 0, sizeof(packet));
	if (send_hello_packet(packet,(char *) macaddr, get_bogus_mac()) < 0) {
		printf("cannot send hello packet\n");
		fexit(1);
	}

	device_info_t di;
	di.d = d;
	di.macaddr = macaddr;
	pcap_loop(adh, 0, packet_handler, (unsigned char *)&di);

	//pcap_freealldevs(alldevs);
	//pcap_close(adhandle);

	return 0;
}
