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
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "common.h"
#include "monocypher.h"
#include "jsmn.h"

int fexit(int code)
{
	printf("\nexit: exiting with code %d\n", code);
	fflush(stderr);
	fflush(stdout);
	exit(code);
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

	srand((unsigned) time(&t));

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

char *hexnums = "0123456789ABCDEF";

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
				printf("fromhex: numbers array not big enough %d %d\n", j, numlen);
				return -1;
			}

			//printf("%d %.2X\n",j,val&0xff);
			numbers[j++] = val & 0xff;

			val = 0;
		}
	}
	
	return j;
}

int g_id = 1000;

int get_id_seq()
{
	return g_id++;		/* XXX randomly generate better initial sequence id */
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
					strncpy(msg->params[j],	instr + g->start, slen);
				} else {
					printf("slen too long %d\n",slen);
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
