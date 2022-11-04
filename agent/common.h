#define PORT	 28080
#define MAXLINE 1460
#define MINMSG  200
#define NUM_PARAMS 8
#define MSLEN 64
#define PLEN 128

typedef struct {
	int num_params;
	uint8_t type[MSLEN + 1];
	uint8_t id[MSLEN + 1];
	uint8_t params[NUM_PARAMS][PLEN + 1];
} message_t;

#ifdef WIN32
#define print_error(msg) printf("%s %d\n",(msg), WSAGetLastError())
#else
#define print_error(msg) perror(msg) 
#endif

#define KSLEN 32
#define SIGLEN 64
#define NONCE_LEN 24
#define MAC_LEN 16

typedef struct {
	uint8_t secret_key[KSLEN];
	uint8_t public_key[KSLEN];
	uint8_t signature_public_key[KSLEN];
	uint8_t shared_secret[KSLEN];
	uint8_t unique_id[KSLEN]; 
	uint8_t peer_public_key[KSLEN];
	uint8_t mac[MAC_LEN];
	uint8_t signature[SIGLEN];
	uint8_t nonce[NONCE_LEN];
} crypto_ctx_t;

#define SLEN 256

int fexit(int code);
char *get_msg_template();
int fillin_secret_key(crypto_ctx_t * ctx);

int tohex(char *numbers, int numlen, int base, char *outbuf);
int fromhex(char *numbers, int numlen, int base, char *inbuf);
int get_id_seq();

int json_parse(char *instr, message_t * msg);
