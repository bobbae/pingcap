#define PORT	 28080
#define MAXLINE 1460
#define NUM_PARAMS 8
#define MSLEN 64
#define PLEN 128

typedef struct {
	int num_params;
	char type[MSLEN + 1];
	char id[MSLEN + 1];
	char params[NUM_PARAMS][PLEN + 1];
} message_t;

#ifdef WINNT
#define print_error(msg) printf("%s %d\n",(msg), WSAGetLastError())
#else
#define perror(msg) 
#endif

#define KSLEN 32
#define SIGLEN 64
#define NONCE_LEN 24
#define MAC_LEN 16

typedef struct {
	char secret_key[KSLEN];
	char public_key[KSLEN];
	char signature_public_key[KSLEN];
	char shared_secret[KSLEN];
	char unique_id[KSLEN]; 
	char peer_public_key[KSLEN];
	char mac[MAC_LEN];
	char signature[SIGLEN];
	char nonce[NONCE_LEN];
} crypto_ctx_t;

#define SLEN 256
