#ifndef __COMMON_H__
#define __COMMON_H__ 1

#define PORT	 28080
#define MAXLINE 1460
#define MAXBUF 4000
#define MINMSG  50
#define NUM_PARAMS 8
#define MSLEN 64
#define PLEN 128
#define KSLEN 32
#define SIGLEN 64
#define NONCE_LEN 24
#define MAC_LEN 16
#define SLEN 256

typedef struct {
	uint8_t type[MSLEN + 1];
	uint8_t id[MSLEN + 1];
	uint8_t unique_id[PLEN + 1];
	uint8_t signature[SLEN + 1];
	uint8_t signature_public_key[PLEN + 1];
	uint8_t public_key[PLEN + 1];
	uint8_t mac[PLEN + 1];
	uint8_t nonce[PLEN + 1];
	uint8_t cipher_text[PLEN + 1];
	uint8_t plain_text[PLEN + 1];
	uint8_t extra[PLEN + 1];	
} message_t;

#ifdef WIN32
#define print_error(msg) printf("%s %d\n",(msg), WSAGetLastError())
#endif

#ifdef LINUX
#define print_error(msg) perror(msg)
#endif


typedef struct {
	uint8_t secret_key[KSLEN];
	uint8_t public_key[KSLEN];
	uint8_t signature_public_key[KSLEN];
	uint8_t unique_id[KSLEN];
	uint8_t signature[SIGLEN];
	uint8_t mac[MAC_LEN];
	uint8_t nonce[NONCE_LEN];
	char unique_id_str[SLEN], signature_str[SLEN];
	char signature_public_key_str[SLEN], public_key_str[SLEN];
	char nonce_str[MSLEN + 1], mac_str[MSLEN + 1];
} crypto_ctx_t;


typedef struct {
	pcap_if_t *d;
	unsigned char *macaddr;
	int sockfd;
	struct sockaddr_in servaddr;
} device_info_t;

int fexit(int code);
char *get_msg_template();
int fillin_secret_key(crypto_ctx_t * ctx);
int tohex(char *numbers, int numlen, int base, char *outbuf);
int fromhex(char *numbers, int numlen, int base, char *inbuf);
int get_id_seq();
void get_unique_id(crypto_ctx_t * ctx, int *idval, int idval_size);
int json_parse(char *instr, message_t * msg);
void init_my_cctx(int idval[], int idlen);
int parse_msg(char *buffer, message_t * msg);
int verify_signature(message_t * msg);
pcap_t *pcap_dev_setup(pcap_if_t * d);
pcap_if_t *init_alldevs();
char *getmac(char *name);
int list_devs(pcap_if_t * adevs);
void init_wsock();
void fill_ether_header(char *header,unsigned char *src, unsigned char *dst);
void fill_str(crypto_ctx_t *cctx);
crypto_ctx_t *get_my_cctx();
pcap_t *get_adhandle();
int get_num_devices();
int show_devs();
int startswith(char *str, char *prefix);
int endswith(char *str, char *suffix);
int msg_type_check(char *msgtype);
int encrypt_send(char *myaddr, char *dstaddr, char *peer_pub, char *msgtype, char *plain_text, char *extra);
int encrypt_send_packet(char *buffer, char *peer_pub, char *msgtype, char *plain_text, char *extra);
char *get_plain_template();
#endif
