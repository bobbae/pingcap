#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#ifdef WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "pcap.h"
#include "monocypher.h"
#include "jsmn.h"
#include "common.h"

int g_id = 1000; // XXX
crypto_ctx_t my_cctx;
char mac_addr_buf[20];
char *hexnums = "0123456789ABCDEF";
pcap_if_t *alldevs = 0;
int alldevs_initialized = 0;
pcap_t *adhandle = 0;
int num_devices = 0;
char errbuf[PCAP_ERRBUF_SIZE];

crypto_ctx_t *get_my_cctx() 
{
	return &my_cctx;
}

int fexit(int code)
{
	printf("\nexit: exiting with code %d\n", code);
	fflush(stderr);
	fflush(stdout);
	exit(code);
}

void get_unique_id(crypto_ctx_t * ctx, int *idval, int idval_size)
{
	int i;

	for (i = 0; i < idval_size; i++) {
		ctx->unique_id[i] = idval[i];
	}
}

char *get_msg_template()
{
	return "{\"type\": \"%s\", \"id\": \"%d\", "
	    " \"params\": [\"%s\", \"%s\", \"%s\", \"%s\",\"%s\",\"%s\",\"%s\",\"%s\" ] }";
}

int fillin_secret_key(crypto_ctx_t * ctx)
{
	int i;
	time_t t;

	srand((unsigned)time(&t));

	if (!ctx) {
		return -1;
	}
	for (i = 0; i < KSLEN; i++) {
		ctx->secret_key[i] = rand() & 0xff;	// terrible "secret" key for demo only
	}

	for (i = 0; i < NONCE_LEN; i++) {
		ctx->nonce[i] = rand() & 0xff;
	}
	return 1;
}


int tohex(char *numbers, int numlen, int base, char *outbuf)
{
	int i = 0;
	int j = 0;
	int n, num;

	if (numlen < 1) {
		return -1;
	}
	while (j < numlen) {
		num = numbers[j++];
		n = num >> 4;
		n = n & 0xf;
		outbuf[i++] = hexnums[n % base];
		n = num & 0xf;
		outbuf[i++] = hexnums[n % base];	// XXX check outbuf overflow
	}

	outbuf[i] = 0;
	//printf("tohex: returning %s\n", outbuf);
	return i;
}

int fromhex(char *numbers, int numlen, int base, char *inbuf)
{
	int val;
	int i = 0;
	int j = 0;

	if (numlen < 1) {
		return -1;
	}

	while (*inbuf) {
		uint8_t byte = *inbuf++;	// XXX check inbuf overflow
		if (byte >= '0' && byte <= '9') {
			byte = byte - '0';
		} else if (byte >= 'A' && byte <= 'F') {	// XXX lowercase 'a' 'f'
			byte = byte - 'A' + 10;
		} else {
			printf("fromhex: Invalid input\n");
			return -1;
		}
		i++;
		val = (val << 4) | (byte & 0xf);
		if ((i % 2) == 0) {
			if (j > numlen) {
				printf
				    ("fromhex: numbers array not big enough %d %d\n",
				     j, numlen);
				return -1;
			}
			//printf("%d %.2X\n",j,val&0xff);
			numbers[j++] = val & 0xff;

			val = 0;
		}
	}

	return j;
}

int get_id_seq()
{
	return g_id++;	
}

int jsoneq(const char *json, jsmntok_t * tok, const char *s)
{
	if (tok->type == JSMN_STRING
	    && (int)strlen(s) == tok->end - tok->start
	    && strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

int json_parse(char *instr, message_t * msg)
{
	int i, j, r;
	int slen;
	jsmn_parser p;
	jsmntok_t t[128];	/* XXX max 128 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, instr, strlen(instr), t, sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}
	memset((void *)msg, 0, sizeof(*msg));

	if (r < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return -1;
	}

	for (i = 1; i < r; i++) {
		if (jsoneq(instr, &t[i], "type") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg->type, instr + t[i].start, slen);
			}
		} else if (jsoneq(instr, &t[i], "id") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg->id, instr + t[i].start, slen);
			}
		} else if (jsoneq(instr, &t[i], "params") == 0) {
			if (t[i + 1].type != JSMN_ARRAY) {
				continue;
			}
			for (j = 0; j < t[i + 1].size && j < NUM_PARAMS; j++) {
				jsmntok_t *g = &t[i + j + 2];
				slen = g->end - g->start;
				//printf("j %d slen %d\n", j, slen);
				if (slen < SLEN) {
					strncpy(msg->params[j],
						instr + g->start, slen);
				} else {
					printf("slen too long %d\n", slen);
				}
				msg->num_params++;
			}
			i += t[i + 1].size + 1;
		} else {
			printf("Unexpected key: %.*s\n", t[i].end - t[i].start,
			       instr + t[i].start);
		}
	}
	/*
	   printf("type %s id %s\n", msg->type, msg->id);
	   for (j = 0; j < msg->num_params; j++) {
	   printf("%d: %s\n", j, msg->params[j]);
	   }
	 */

	return msg->num_params;
}

void init_my_cctx(int idval[], int idlen)
{
	memset((void *)&my_cctx, 0, sizeof(my_cctx));

	fillin_secret_key(&my_cctx);
	crypto_sign_public_key(my_cctx.signature_public_key,
			       my_cctx.secret_key);
	get_unique_id(&my_cctx, idval, idlen);
	crypto_sign(my_cctx.signature, my_cctx.secret_key,
		    my_cctx.signature_public_key, my_cctx.unique_id, KSLEN);

	crypto_x25519_public_key(my_cctx.public_key, my_cctx.secret_key);
}


void fill_str(crypto_ctx_t *cctx)
{
	memset((void *)cctx->unique_id_str, 0, sizeof(cctx->unique_id_str));
	memset((void *)cctx->signature_str, 0, sizeof(cctx->signature_str));
	memset((void *)cctx->signature_public_key_str, 0, sizeof(cctx->signature_public_key_str));
	memset((void *)cctx->public_key_str, 0, sizeof(cctx->public_key_str));
	memset((void *)cctx->nonce_str, 0, sizeof(cctx->nonce_str));
	memset((void *)cctx->mac_str, 0, sizeof(cctx->mac_str));

	tohex(cctx->unique_id, KSLEN, 16, cctx->unique_id_str);
	tohex(cctx->signature, SIGLEN, 16, cctx->signature_str);
	tohex(cctx->signature_public_key, KSLEN, 16, cctx->signature_public_key_str);
	tohex(cctx->public_key, KSLEN, 16, cctx->public_key_str);
	tohex(cctx->mac, MAC_LEN, 16, cctx->mac_str);
	tohex(cctx->nonce, NONCE_LEN, 16, cctx->nonce_str);
}

int parse_msg(char *buffer, message_t * msg)
{
	if (!buffer || !msg)
		return -1;
	memset((void *)msg, 0, sizeof(*msg));
	if (json_parse(buffer, msg) < 0) {
		//printf("cannot parse message\n");
		return -3;
	}
	/*
	   printf("msg type %s id %s num_params %d params %s %s %s %s %s %s %s %s\n",
	   msg.type, msg.id, msg.num_params,
	   msg.params[0], msg.params[1], msg.params[2], msg.params[3],
	   msg.params[4], msg.params[5], msg.params[6], msg.params[7]);
	 */
	return 1;
}

int verify_signature(message_t * msg)
{
	crypto_ctx_t cctx;

	memset((void *)&cctx, 0, sizeof(cctx));
	fromhex(cctx.unique_id, KSLEN, 16, msg->params[0]);
	fromhex(cctx.signature, SIGLEN, 16, msg->params[1]);
	fromhex(cctx.signature_public_key, KSLEN, 16, msg->params[2]);

	if (crypto_check
	    (cctx.signature, cctx.signature_public_key, cctx.unique_id,
	     KSLEN)) {
		//printf("signature is corrupt\n");
		return -9;
	}
	//printf("signature is verified\n");
	return 1;
}


pcap_t *get_adhandle() 
{
	return adhandle;
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

int get_num_devices()
{
	return num_devices;
}

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
#endif
#ifdef LINUX
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

void fill_ether_header(char *packet, char *src, char *dst)
{
	packet[0] = dst[0];
	packet[1] = dst[1];
	packet[2] = dst[2];
	packet[3] = dst[3];
	packet[4] = dst[4];
	packet[5] = dst[5];

	packet[6] = src[0];
	packet[7] = src[1];
	packet[8] = src[2];
	packet[9] = src[3];
	packet[10] = src[4];
	packet[11] = src[5];

	packet[12] = 0xda;	//XXX
	packet[13] = 0xda;
}

void init_wsock() 
{
#ifdef WIN32
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) 
		print_error("WSAStartup failed");
#endif
}
