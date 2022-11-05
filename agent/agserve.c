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
#else
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
#include "common.h"
#include "monocypher.h"

typedef struct {
	pcap_if_t *d;
	unsigned char *macaddr;
} device_info_t;

static int get_unique_id(crypto_ctx_t * ctx)
{
	int idval[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};			/* XXX  */
	int i;

	for (i = 0; i < sizeof(idval) / sizeof(int); i++) {
		ctx->unique_id[i] = idval[i];
	}
	return 1;
}

int handle_msg(char *buffer)
{
	message_t msg;
	crypto_ctx_t cctx;

	memset((void *)&msg, 0, sizeof(msg));
	if (json_parse(buffer, &msg) < 0) {
		//printf("cannot parse message\n");
		return -3;
	}

	/*
	   printf("msg type %s id %s num_params %d params %s %s %s %s %s %s %s %s\n",
	   msg.type, msg.id, msg.num_params,
	   msg.params[0], msg.params[1], msg.params[2], msg.params[3],
	   msg.params[4], msg.params[5], msg.params[6], msg.params[7]);
	 */

	char msgtype[MSLEN + 1];
	strcpy(msgtype, msg.type);

	memset((void *)&cctx, 0, sizeof(cctx));

	fromhex(cctx.unique_id, KSLEN, 16, msg.params[0]);
	fromhex(cctx.signature, SIGLEN, 16, msg.params[1]);
	fromhex(cctx.signature_public_key, KSLEN, 16, msg.params[2]);

	int id_seq = get_id_seq();
	char unique_id_str[SLEN], signature_str[SLEN];
	char signature_public_key_str[SLEN], public_key_str[SLEN];

	memset((void *)unique_id_str, 0, sizeof(unique_id_str));
	memset((void *)signature_str, 0, sizeof(signature_str));
	memset((void *)signature_public_key_str, 0,
	       sizeof(signature_public_key_str));
	memset((void *)public_key_str, 0, sizeof(public_key_str));

	tohex(cctx.unique_id, KSLEN, 16, unique_id_str);
	tohex(cctx.signature, SIGLEN, 16, signature_str);
	tohex(cctx.signature_public_key, KSLEN, 16, signature_public_key_str);

	/*
	   printf("uniq id %s signature %s signature public key %s\n", 
	   unique_id_str, signature_str, signature_public_key_str);
	 */

	if (crypto_check
	    (cctx.signature, cctx.signature_public_key, cctx.unique_id,
	     KSLEN)) {
		//printf("signature is corrupt\n");
		return -9;
	} else {
		//printf("signature is verified\n");
	}

	memset((void *)&cctx, 0, sizeof(cctx));

	fillin_secret_key(&cctx);
	crypto_sign_public_key(cctx.signature_public_key, cctx.secret_key);
	get_unique_id(&cctx);
	crypto_sign(cctx.signature, cctx.secret_key, cctx.signature_public_key,
		    cctx.unique_id, KSLEN);

	crypto_x25519_public_key(cctx.public_key, cctx.secret_key);

	memset((void *)unique_id_str, 0, sizeof(unique_id_str));
	memset((void *)signature_str, 0, sizeof(signature_str));
	memset((void *)signature_public_key_str, 0,
	       sizeof(signature_public_key_str));
	memset((void *)public_key_str, 0, sizeof(public_key_str));

	tohex(cctx.unique_id, KSLEN, 16, unique_id_str);
	tohex(cctx.signature, SIGLEN, 16, signature_str);
	tohex(cctx.signature_public_key, KSLEN, 16, signature_public_key_str);
	tohex(cctx.public_key, KSLEN, 16, public_key_str);

	fromhex(cctx.peer_public_key, KSLEN, 16, msg.params[3]);

	crypto_x25519(cctx.shared_secret, cctx.secret_key,
		      cctx.peer_public_key);

	char cipher_text[MSLEN + 1];
	char nonce_str[MSLEN + 1], mac_str[MSLEN + 1];
	char cipher_text_str[MSLEN + 1];
	char *plain_text = "this is a secret";	// XXX

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)cipher_text_str, 0, sizeof(cipher_text_str));

	crypto_lock(cctx.mac, cipher_text, cctx.shared_secret, cctx.nonce,
		    plain_text, strlen(plain_text));
	//printf("plain_text %d %s\n", strlen(plain_text), plain_text);
	//printf("cipher_text %d %s\n", strlen(cipher_text),cipher_text);

	tohex(cctx.mac, MAC_LEN, 16, mac_str);
	tohex(cctx.nonce, NONCE_LEN, 16, nonce_str);
	tohex(cipher_text, strlen(plain_text), 16, cipher_text_str);
	//printf("cipher_text_str %d %s\n", strlen(cipher_text_str), cipher_text_str);

	// XXX params: unique_id, signature, signature_public_key, public_key, mac, nonce, cipher_text, empty
	strcat(msgtype, "resp");
	sprintf(buffer, (char *)get_msg_template(), msgtype, id_seq++,
		unique_id_str, signature_str, signature_public_key_str,
		public_key_str, mac_str, nonce_str, cipher_text_str, "");

	return 0;
}

int proc_sock(int port)
{
	int sockfd, n, salen;
	struct sockaddr_in servaddr;
	char buffer[MAXLINE];

#ifdef WIN32
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) {
		print_error("WSAStartup failed");
		return -1;
	}
#endif

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

	return 0;
}

pcap_if_t *alldevs = 0;
pcap_t *adhandle = 0;
int alldevs_initialized = 0;
int num_devices = 0;
char errbuf[PCAP_ERRBUF_SIZE];
int devnum = -1;

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data)
{
	const u_char *message;
	u_char *pktbuf, packet[1500];
	int i;
	device_info_t *di = (device_info_t *) param;

	message = pkt_data + 14;
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
	packet[0] = pkt_data[6];
	packet[1] = pkt_data[7];
	packet[2] = pkt_data[8];
	packet[3] = pkt_data[9];
	packet[4] = pkt_data[10];
	packet[5] = pkt_data[11];

	packet[6] = di->macaddr[0];
	packet[7] = di->macaddr[1];
	packet[8] = di->macaddr[2];
	packet[9] = di->macaddr[3];
	packet[10] = di->macaddr[4];
	packet[11] = di->macaddr[5];

	packet[12] = 0xda;
	packet[13] = 0xda;

	int pkt_len = 14 + strlen(pktbuf);

	if (pcap_sendpacket(adhandle, packet, pkt_len) != 0) {
		printf("\nError sending the packet: %s\n",
		       pcap_geterr(adhandle));
		return;
	}
	printf("sent %d bytes\n", pkt_len);
}

pcap_t *pcap_dev_setup(pcap_if_t * d)
{
	char packet_filter[] = "ether proto 0xdada";
	struct bpf_program fcode;

	if (adhandle)
		return adhandle;

	if ((adhandle =
	     pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Pcap\n",
			d->name);
		return 0;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr,
			"\nThis program works only on Ethernet networks.\n");
		return 0;
	}

	u_int netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		return 0;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		return 0;
	}
	return adhandle;
}

pcap_if_t *init_alldevs()
{
	int i;

	if (alldevs_initialized)
		return alldevs;

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	alldevs_initialized = 1;
	pcap_if_t *d;
	for (d = alldevs, i = 0; d; d = d->next, i++) ;
	num_devices = i;
	return alldevs;
}

char mac_addr_buf[20];

char *getmac(char *name)
{
	memset((void *)mac_addr_buf, 0, sizeof(mac_addr_buf));
#ifdef WIN32
	IP_ADAPTER_INFO adapter_info[32];
	int alen = sizeof(adapter_info);
	int status = GetAdaptersInfo(adapter_info, (PULONG) & alen);
	if (status != ERROR_SUCCESS)
		return mac_addr_buf;
	IP_ADAPTER_INFO *pa = adapter_info;
	while (pa) {
		if (pa->Type == MIB_IF_TYPE_ETHERNET &&
		    strcmp(pa->AdapterName, name) == 0) {
			mac_addr_buf[0] = pa->Address[0];
			mac_addr_buf[1] = pa->Address[1];
			mac_addr_buf[2] = pa->Address[2];
			mac_addr_buf[3] = pa->Address[3];
			mac_addr_buf[4] = pa->Address[4];
			mac_addr_buf[5] = pa->Address[5];
			//printf("%s %s %s\n",pa->AdapterName, pa->Description,mac_addr_buf);
			return mac_addr_buf;
		}
		pa = pa->Next;
	}
	return mac_addr_buf;
#else
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, name);
	int res = ioctl(fd, SIOCGIFHWADDR, &s);
	close(fd);

	if (res != 0)
		return mac_addr_buf;

	mac_addr_buf[0] = s.ifr_addr.sa_data[0];
	mac_addr_buf[1] = s.ifr_addr.sa_data[1];
	mac_addr_buf[2] = s.ifr_addr.sa_data[2];
	mac_addr_buf[3] = s.ifr_addr.sa_data[3];
	mac_addr_buf[4] = s.ifr_addr.sa_data[4];
	mac_addr_buf[5] = s.ifr_addr.sa_data[5];
	return mac_addr_buf;
#endif
}

int list_devs(pcap_if_t * adevs)
{
	pcap_if_t *d;
	pcap_addr_t *paddr;

	int i = 0;
	for (d = adevs; d; d = d->next) {
		printf("%d) %s", i++, d->name);
		if (d->description)
			printf(" (%s)", d->description);
		else
			printf(" (No description available)");
		if (d->addresses && d->addresses->addr) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)d->addresses->addr;
			printf(" %s", inet_ntoa(sin->sin_addr));
		}
		unsigned char *macaddr = getmac(d->name);
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
		       macaddr[0], macaddr[1], macaddr[2], macaddr[3],
		       macaddr[4], macaddr[5]);
		printf("\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure Pcap is installed.\n");
		return -1;
	}
}

int print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h       print help\n");
	printf("-s       use socket\n");
	printf("-p       use pcap\n");
	printf("-l       list network interfaces\n");
	printf("-d index use network interface index\n");
	printf("-p port  use port\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int c;
	int use_sock = 0, port = PORT, list_ifs = 0;

	opterr = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	while ((c = getopt(argc, argv, "hslp:d:")) != -1) {
		switch (c) {
		case 'h':
			print_help(argv[0]);
			return 0;
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
			return 1;
		default:
			fprintf(stderr, "unknown option %c.\n", c);
			return 2;
		}
	}

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
		if (num_devices < 1) {
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
		if (devnum >= num_devices) {
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
