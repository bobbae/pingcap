#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#ifdef WINNT
#include <WinSock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "common.h"
#include "monocypher.h"

int get_unique_id(crypto_ctx_t * ctx)
{
	int idval[] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
		0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0
	};			/* XXX random ID */
	int i;

	for (i = 0; i < sizeof(idval) / sizeof(int); i++) {
		ctx->unique_id[i] = idval[i];
	}
	return 1;
}


int main(int argc, char *argv[])
{
	int sockfd;
	char buffer[MAXLINE];
	struct sockaddr_in servaddr;
	struct hostent *he;
	crypto_ctx_t cctx;

#ifdef WINNT
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != NO_ERROR) {
		print_error("WSAStartup failed");
		fexit(3);
	}
#endif

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	//servaddr.sin_addr.s_addr = INADDR_ANY;

	if (argc < 2) {
		printf("Usage: %s hostname\nhostname required\n", argv[0]);
		fexit(1);
	}

	char *hostname = argv[1];

	if ((he = gethostbyname(hostname)) == NULL) {
		unsigned long ina = inet_addr(hostname);
		if (ina == -1) {
			print_error
			    ("gethostbyname failed and invalid IP address");
			fexit(7);
		}
		servaddr.sin_addr.s_addr = ina;
	} else {
		memcpy(&servaddr.sin_addr, he->h_addr_list[0], he->h_length);
	}
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		fexit(3);
	}

	memset((void *)&cctx, 0, sizeof(cctx));
	fillin_secret_key(&cctx);
	crypto_sign_public_key(cctx.signature_public_key, cctx.secret_key);
	get_unique_id(&cctx);
	
	crypto_sign(cctx.signature, cctx.secret_key, cctx.signature_public_key,
		    cctx.unique_id, KSLEN);

	crypto_x25519_public_key(cctx.public_key, cctx.secret_key);

	int id_seq = get_id_seq();

	char unique_id_str[SLEN], signature_str[SLEN];
	char signature_public_key_str[SLEN], public_key_str[SLEN];
	memset((void *)unique_id_str, 0, sizeof(unique_id_str));
	memset((void *)signature_str, 0, sizeof(signature_str));
	memset((void *)signature_public_key_str, 0, sizeof(signature_public_key_str));
	memset((void *)public_key_str, 0, sizeof(public_key_str));
							
	tohex(cctx.unique_id, KSLEN, 16, unique_id_str);
	tohex(cctx.signature, SIGLEN, 16, signature_str);
	tohex(cctx.signature_public_key, KSLEN, 16,  signature_public_key_str);
	tohex(cctx.public_key, KSLEN, 16,  public_key_str);

	/* printf("uniq id %s signature %s signature public key %s public key %s\n", 
	       unique_id_str, signature_str, signature_public_key_str, public_key_str);
	*/
	
	sprintf(buffer, (char *)get_msg_template(), "hello", id_seq++,
		unique_id_str, signature_str, signature_public_key_str,
		public_key_str, "", "", "", "");

	int n, len;

	n = sendto(sockfd, (const char *)buffer, strlen(buffer),
		   0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	if (n < 0) {
		print_error("sendto failed");
		fexit(5);
	}
	printf("Sent %d bytes, %s\n", n, buffer);

	len = sizeof(servaddr);
	n = recvfrom(sockfd, (char *)buffer, MAXLINE,
		     0, (struct sockaddr *)&servaddr, &len);
	if (n < 0) {
		print_error("recvfrom failed");
		fexit(6);
	}
	buffer[n] = '\0';
	printf("Received %d bytes, %s\n", n, buffer);

	message_t msg;
	memset((void *)&msg, 0, sizeof(msg));
	if (json_parse(buffer, &msg) < 0) {
		printf("cannot parse message\n");
		fexit(3);
	}
	/*
	printf("msg type %s id %s num_params %d params %s %s %s %s %s %s %s %s\n",
	       msg.type, msg.id, msg.num_params,
	       msg.params[0], msg.params[1], msg.params[2], msg.params[3],
	       msg.params[4], msg.params[5], msg.params[6], msg.params[7]);
	*/
	
	fromhex(cctx.peer_public_key, KSLEN, 16, msg.params[3]);
	fromhex(cctx.mac, MAC_LEN, 16, msg.params[4]);
	fromhex(cctx.nonce, NONCE_LEN, 16, msg.params[5]);

	crypto_x25519(cctx.shared_secret, cctx.secret_key, cctx.peer_public_key);

	char cipher_text[MSLEN + 1], plain_text[MSLEN + 1];
	char cipher_text_str[MSLEN + 1];

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)plain_text, 0, sizeof(plain_text));
	memset((void *)cipher_text_str, 0, sizeof(cipher_text_str));	
	fromhex(cipher_text, MSLEN, 16, msg.params[6]);
	//printf("received cipher_text %d %s\n", strlen(cipher_text), cipher_text);
	if (crypto_unlock(plain_text, cctx.shared_secret, cctx.nonce, cctx.mac, cipher_text, strlen(cipher_text))) {
		printf("error: cannot decrypt\n");
	} else {
		printf("decrypted: %s\n", plain_text);
	}
	close(sockfd);
	return 0;
}
