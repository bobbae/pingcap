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
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#endif

#include "pcap.h"
#include "monocypher.h"
#include "jsmn.h"
#include "common.h"

int g_id = 1000;		// XXX
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
	    " \"uniqueId\": \"%s\", \"signature\": \"%s\", "
	    " \"signaturePublicKey\": \"%s\", \"publicKey\": \"%s\", "
	    " \"mac\": \"%s\", \"nonce\": \"%s\", "
	    " \"cipherText\": \"%s\", \"extra\": \"%s\" }";
}

char *get_plain_template()
{
	return
	    "{\"type\": \"%s\", \"publicKey\": \"%s\", \"plainText\": \"%s\", "
	    "  \"extra\": \"%s\" }";
}

char *get_relay_template()
{
	return "{\"type\": \"%s\", \"id\": \"%d\", "
	    " \"myEthAddr\": \"%s\", \"peerPublicKey\": \"%s\", "
	    " \"srcEthAddr\": \"%s\", \"etherType\": \"%s\", "
	    " \"plainText\": \"%s\", " " \"extra\": \"%s\" }";
}

int startswith(char *str, char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

int endswith(char *str, char *suffix)
{
	int slen = strlen(str);
	int suffixlen = strlen(suffix);

	if (suffixlen > slen)
		return -1;
	return strcmp(str + slen - suffixlen, suffix) == 0;
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
		} else if (byte >= 'A' && byte <= 'F') {
			byte = byte - 'A' + 10;
		} else if (byte >= 'a' && byte <= 'f') {
			byte = byte - 'a' + 10;
		} else {
			printf("error: fromhex invalid input\n");
			return -1;
		}
		i++;
		val = (val << 4) | (byte & 0xf);
		if ((i % 2) == 0) {
			if (j > numlen) {
				printf
				    ("error: fromhex numbers array not big enough %d %d\n",
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

int msg_type_check(char *msgtype)
{
	char *valid_msgtypes[] = { "hello", "ping", "info", "config", "scan" };
	int i;
	for (i = 0; i < sizeof(valid_msgtypes) / sizeof(char *); i++) {
		if (strcmp(valid_msgtypes[i], msgtype) == 0)
			return 1;
	}
	return 0;
}

int encrypt_send(char *myaddr, char *dstaddr, char *peer_pub, char *msgtype,
		 char *plain_text, char *extra)
{
	char buffer[MAXLINE];

	char myaddrbytes[7], dstaddrbytes[7];
	memset((void *)myaddrbytes, 0, sizeof(myaddrbytes));
	memset((void *)dstaddrbytes, 0, sizeof(dstaddrbytes));
	sscanf(myaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
	       &myaddrbytes[0],
	       &myaddrbytes[1],
	       &myaddrbytes[2], &myaddrbytes[3], &myaddrbytes[4],
	       &myaddrbytes[5]);
	sscanf(dstaddr, "%02x:%02x:%02x:%02x:%02x:%02x", &dstaddrbytes[0],
	       &dstaddrbytes[1], &dstaddrbytes[2], &dstaddrbytes[3],
	       &dstaddrbytes[4], &dstaddrbytes[5]);

	fill_ether_header((char *)buffer, (unsigned char *)myaddrbytes,
			  (unsigned char *)dstaddrbytes);

	return encrypt_send_packet(buffer, peer_pub, msgtype,
				   plain_text, extra);
}

int encrypt_send_packet(char *buffer, char *peer_pub, char *msgtype,
			char *plain_text, char *extra)
{
	char cipher_text[MSLEN + 1], cipher_text_str[MSLEN + 1];
	crypto_ctx_t *cctx = get_my_cctx();
	uint8_t peer_public_key[KSLEN];

	//printf("encrypt_send_packet msgtype %s peer_pub %s plain_text %s\n",msgtype, peer_pub, plain_text);

	fromhex(peer_public_key, KSLEN, 16, peer_pub);

	uint8_t shared_secret[KSLEN];
	memset((void *)shared_secret, 0, sizeof(shared_secret));
	crypto_x25519(shared_secret, cctx->secret_key, peer_public_key);
	uint8_t shared_secret_str[SLEN];
	memset((void *)shared_secret_str, 0, sizeof(shared_secret_str));
	tohex(shared_secret, KSLEN, 16, shared_secret_str);

	//printf("encrypting with shared_secret %s peer_pub %s\n", shared_secret_str, peer_public_key);

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)cipher_text_str, 0, sizeof(cipher_text_str));

	crypto_lock(cctx->mac, cipher_text, shared_secret,
		    cctx->nonce, plain_text, strlen(plain_text));
	fill_str(cctx);
	//printf("plain_text %d %s\n", (int)strlen(plain_text), plain_text);

	tohex(cipher_text, strlen(plain_text), 16, cipher_text_str);
	//printf("cipher_text_str %d %s\n", (int)strlen(cipher_text_str), cipher_text_str);

	char *bp = &buffer[14];
	sprintf(bp, (char *)get_msg_template(), msgtype, get_id_seq(),
		cctx->unique_id_str, cctx->signature_str,
		cctx->signature_public_key_str, cctx->public_key_str,
		cctx->mac_str, cctx->nonce_str, cipher_text_str, extra);
	//printf("pcap send encrypted msg %s\n", buffer);

	if (pcap_sendpacket(get_adhandle(), buffer, strlen(bp) + 14) != 0) {
		printf("error: sending encrypted msg\n");
		return -1;
	}
	//printf("sent encrypted msg %d, %s\n", strlen(bp)+14, bp);
	return 1;
}

int json_parse(char *instr, message_t * msg)
{
	int i, j, r;
	int slen;
	jsmn_parser p;
	jsmntok_t t[128];	/* XXX max 128 tokens */

	//printf("parsing json %s\n", instr);
	jsmn_init(&p);
	r = jsmn_parse(&p, instr, strlen(instr), t, sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("error: failed to parse JSON: %d\n", r);
		return -1;
	}

	memset((void *)msg, 0, sizeof(*msg));

	if (r < 1 || t[0].type != JSMN_OBJECT) {
		printf("error: JSON object expected\n");
		return -1;
	}

	for (i = 1; i < r; i++) {
		if (jsoneq(instr, &t[i], "type") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg->type, instr + t[i].start, slen);
			}
			//printf("msgtype %s\n", msg->type);
		} else if (jsoneq(instr, &t[i], "id") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg->id, instr + t[i].start, slen);
			}
			//printf("id %s\n", msg->id);                                   
		} else if (jsoneq(instr, &t[i], "uniqueId") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->unique_id, instr + t[i].start,
					slen);
			}
			//printf("uniqueId %s\n", msg->unique_id);
		} else if (jsoneq(instr, &t[i], "signature") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < SLEN) {
				strncpy(msg->signature, instr + t[i].start,
					slen);
			}
			//printf("signature %s\n", msg->signature);
		} else if (jsoneq(instr, &t[i], "signaturePublicKey") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->signature_public_key,
					instr + t[i].start, slen);
			}
			//printf("signature_public_key %s\n", msg->signature_public_key);
		} else if (jsoneq(instr, &t[i], "publicKey") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->public_key, instr + t[i].start,
					slen);
			}
			//printf("publicKey %s\n", msg->public_key);
		} else if (jsoneq(instr, &t[i], "mac") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->mac, instr + t[i].start, slen);
			}
			//printf("mac %s\n", msg->mac);
		} else if (jsoneq(instr, &t[i], "nonce") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->nonce, instr + t[i].start, slen);
			}
			//printf("nonce %s\n", msg->nonce);
		} else if (jsoneq(instr, &t[i], "cipherText") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->cipher_text, instr + t[i].start,
					slen);
			}
			//printf("cipher_text %s\n", msg->cipher_text);
		} else if (jsoneq(instr, &t[i], "extra") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->extra, instr + t[i].start, slen);
			}
			//printf("extra %s\n", msg->extra);
		} else if (jsoneq(instr, &t[i], "plainText") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < PLEN) {
				strncpy(msg->plain_text, instr + t[i].start,
					slen);
			}
			//printf("extra %s\n", msg->extra);
		} else {
			printf("error: unexpected JSON key: %.*s\n",
			       t[i].end - t[i].start, instr + t[i].start);
		}
	}

	return i;
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

void fill_str(crypto_ctx_t * cctx)
{
	memset((void *)cctx->unique_id_str, 0, sizeof(cctx->unique_id_str));
	memset((void *)cctx->signature_str, 0, sizeof(cctx->signature_str));
	memset((void *)cctx->signature_public_key_str, 0,
	       sizeof(cctx->signature_public_key_str));
	memset((void *)cctx->public_key_str, 0, sizeof(cctx->public_key_str));
	memset((void *)cctx->nonce_str, 0, sizeof(cctx->nonce_str));
	memset((void *)cctx->mac_str, 0, sizeof(cctx->mac_str));

	tohex(cctx->unique_id, KSLEN, 16, cctx->unique_id_str);
	tohex(cctx->signature, SIGLEN, 16, cctx->signature_str);
	tohex(cctx->signature_public_key, KSLEN, 16,
	      cctx->signature_public_key_str);
	tohex(cctx->public_key, KSLEN, 16, cctx->public_key_str);
	tohex(cctx->mac, MAC_LEN, 16, cctx->mac_str);
	tohex(cctx->nonce, NONCE_LEN, 16, cctx->nonce_str);

	/* printf
	   ("filled unique_id_str %s signature %s signature_public_key %s public_key %s mac %s nonce %s\n",
	   cctx->unique_id_str, cctx->signature_str,
	   cctx->signature_public_key_str, cctx->public_key_str,
	   cctx->mac_str, cctx->nonce_str);
	 */
}

int parse_msg(char *buffer, message_t * msg)
{
	if (!buffer || !msg)
		return -1;

	//printf("parsing msg %s\n", buffer);

	memset((void *)msg, 0, sizeof(*msg));

	if (json_parse(buffer, msg) < 0) {
		//printf("cannot parse message\n");
		return -3;
	}

	return 1;
}

int verify_signature(message_t * msg)
{
	crypto_ctx_t cctx;

	memset((void *)&cctx, 0, sizeof(cctx));
	fromhex(cctx.unique_id, KSLEN, 16, msg->unique_id);
	fromhex(cctx.signature, SIGLEN, 16, msg->signature);
	fromhex(cctx.signature_public_key, KSLEN, 16,
		msg->signature_public_key);

	if (crypto_check
	    (cctx.signature, cctx.signature_public_key, cctx.unique_id, KSLEN))
	{
		printf("error: signature is corrupt\n");
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
			"\nerror: Unable to open the adapter. %s is not supported by Pcap\n",
			d->name);
		return 0;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr,
			"\nerror: This program works only on Ethernet networks.\n");
		return 0;
	}

	u_int netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
			"\nerror: Unable to compile the packet filter. Check the syntax.\n");
		return 0;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nerror: can't the filter.\n");
		return 0;
	}
	return adhandle;
}

pcap_if_t *init_alldevs()
{
	int i;
	pcap_if_t *d;

	if (alldevs_initialized)
		return alldevs;

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("error: pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	alldevs_initialized = 1;
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

	strncpy(s.ifr_name, name, IFNAMSIZ);
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

int show_devs()
{
	pcap_if_t *adevs;
	adevs = init_alldevs();
	if (!adevs) {
		printf("error: cannot list network devices\n");
		return -1;
	}
	list_devs(adevs);
	return 0;
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
		printf
		    ("\nerror: No interfaces found! Make sure pcap is installed.\n");
		return -1;
	}
}

void fill_ether_header(char *packet, unsigned char *src, unsigned char *dst)
{
	/*
	   printf
	   ("fill ether header: dst %02x:%02x:%02x:%02x:%02x:%02x  src %02x:%02x:%02x:%02x:%02x:%02x\n",
	   dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], src[0], src[1],
	   src[2], src[3], src[4], src[5]);
	 */
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
