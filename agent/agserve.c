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
	int idval[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
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

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

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
	servaddr.sin_addr.s_addr = INADDR_ANY;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		print_error("socket creation failed");
		fexit(3);
	}
	if (bind(sockfd, (const struct sockaddr *)&servaddr,
		 sizeof(servaddr)) < 0) {
		print_error("bind failed");
		fexit(5);
	}

	int n, len;

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
		fexit(8);
	}

	printf("msg type %s id %s num_params %d params %s %s %s %s %s %s %s %s\n",
	       msg.type, msg.id, msg.num_params,
	       msg.params[0], msg.params[1], msg.params[2], msg.params[3],
	       msg.params[4], msg.params[5], msg.params[6], msg.params[7]);
	
	
	memset((void *)&cctx, 0, sizeof(cctx));

	fromhex(cctx.unique_id, KSLEN, 16, msg.params[0]);
	fromhex(cctx.signature, SIGLEN, 16, msg.params[1]);
	fromhex(cctx.signature_public_key, KSLEN, 16, msg.params[2]);

	int id_seq = get_id_seq();
	char unique_id_str[SLEN], signature_str[SLEN];
	char signature_public_key_str[SLEN], public_key_str[SLEN];
	memset((void *)unique_id_str, 0, sizeof(unique_id_str));
	memset((void *)signature_str, 0, sizeof(signature_str));
	memset((void *)signature_public_key_str, 0, sizeof(signature_public_key_str));
	memset((void *)public_key_str, 0, sizeof(public_key_str));

	tohex(cctx.unique_id, KSLEN, 16, unique_id_str);
	tohex(cctx.signature, SIGLEN, 16, signature_str);
	tohex(cctx.signature_public_key, KSLEN, 16, signature_public_key_str);
	
	printf("uniq id %s signature %s signature public key %s\n", 
	       unique_id_str, signature_str, signature_public_key_str);

	if (crypto_check(cctx.signature, cctx.signature_public_key, cctx.unique_id, KSLEN)) {
		printf("signature is corrupt\n");
	} else {
		//The unique_id signed by the holder of secret_key is verified using signature_public_key.
		printf("signature is verified\n");
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
	memset((void *)signature_public_key_str, 0, sizeof(signature_public_key_str));
	memset((void *)public_key_str, 0, sizeof(public_key_str));

	tohex(cctx.unique_id, KSLEN, 16, unique_id_str);
	tohex(cctx.signature, SIGLEN, 16, signature_str);
	tohex(cctx.signature_public_key, KSLEN, 16, signature_public_key_str);
	tohex(cctx.public_key, KSLEN, 16, public_key_str);
	
	fromhex(cctx.peer_public_key, KSLEN, 16, msg.params[3]);

	crypto_x25519(cctx.shared_secret, cctx.secret_key, cctx.peer_public_key);


	char cipher_text[MSLEN + 1];
	char nonce_str[MSLEN + 1], mac_str[MSLEN + 1];
	char cipher_text_str[MSLEN + 1];
	char *plain_text = "this is a secret";
	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)cipher_text_str, 0, sizeof(cipher_text_str));
	crypto_lock(cctx.mac, cipher_text, cctx.shared_secret, cctx.nonce, plain_text, strlen(plain_text));
	//printf("plain_text %d %s\n", strlen(plain_text), plain_text);
	//printf("cipher_text %d %s\n", strlen(cipher_text),cipher_text);
	tohex(cctx.mac, MAC_LEN, 16, mac_str);
	tohex(cctx.nonce, NONCE_LEN, 16, nonce_str);
	tohex(cipher_text, strlen(plain_text), 16, cipher_text_str);
	//printf("cipher_text_str %d %s\n", strlen(cipher_text_str), cipher_text_str);

	// XXX params: unique_id, signature, signature_public_key, public_key, mac, nonce, cipher_text, empty
	sprintf(buffer, (char *)get_msg_template(), "hello-resp", id_seq++,
		unique_id_str, signature_str, signature_public_key_str,
		public_key_str, mac_str, nonce_str, cipher_text_str, "");

	n = sendto(sockfd, (const char *)buffer, strlen(buffer),
		   0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	if (n < 0) {
		print_error("sendto failed");
		fexit(5);
	}
	printf("Sent %d bytes, %s\n", n, buffer);

	close(sockfd);
	return 0;
}
