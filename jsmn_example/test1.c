#include "../jsmn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A small example of jsmn parsing when JSON structure is known and number of
 * tokens is predictable.
 */

static const char *JSON_STRING =
    "{\"type\": \"request-info\", \"id\": \"1000\",\n  "
    "\"parameters\": [\"param1\", \"param2\", \"param3\"] }";

static int jsoneq(const char *json, jsmntok_t * tok, const char *s)
{
	if (tok->type == JSMN_STRING
	    && (int)strlen(s) == tok->end - tok->start
	    && strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

#define NUM_PARAMS 10
#define MSLEN 30
typedef struct {
	char type[MSLEN + 1];
	char id[MSLEN + 1];
	int num_params;
	char params[NUM_PARAMS][MSLEN + 1];
} message_t;

int main()
{
	int i;
	int j;
	int slen;
	int r;
	message_t msg;
	jsmn_parser p;
	jsmntok_t t[128];	/* We expect no more than 128 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return 1;
	}
	memset((void *)&msg, 0, sizeof(msg));
	/*
	 * Assume the top-level element is an object 
	 */
	if (r < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return 1;
	}

	/*
	 * Loop over all keys of the root object 
	 */
	for (i = 1; i < r; i++) {
		if (jsoneq(JSON_STRING, &t[i], "type") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg.type, JSON_STRING + t[i].start,
					slen);
			}
		} else if (jsoneq(JSON_STRING, &t[i], "id") == 0) {
			i++;
			slen = t[i].end - t[i].start;
			if (slen < MSLEN) {
				strncpy(msg.id, JSON_STRING + t[i].start, slen);
			}
		} else if (jsoneq(JSON_STRING, &t[i], "parameters") == 0) {
			if (t[i + 1].type != JSMN_ARRAY) {
				continue;	/* We expect groups to be an array of
						 * strings */
			}
			for (j = 0; j < t[i + 1].size && j < NUM_PARAMS; j++) {
				jsmntok_t *g = &t[i + j + 2];
				slen = g->end - g->start;
				if (slen < MSLEN) {
					strncpy(msg.params[j],
						JSON_STRING + g->start, slen);
				}
				msg.num_params++;
			}
			i += t[i + 1].size + 1;
		} else {
			printf("Unexpected key: %.*s\n", t[i].end - t[i].start,
			       JSON_STRING + t[i].start);
		}
	}
	printf("type %s id %s\n", msg.type, msg.id);
	for (j = 0; j < msg.num_params; j++) {
		printf("%d: %s\n", j, msg.params[j]);
	}

	return EXIT_SUCCESS;
}
