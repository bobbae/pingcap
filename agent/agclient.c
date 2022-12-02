#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>

/* 
Current code is runnable on typical Linux and Windows machines.
The client side agent code is intended to run on devices that are
managed. Remote manager program interfaces with this agent via
agent server located in agserve/ directory here.

The code here is intended to minimize dependencies. 
Deliberate use of one file monocypher and jsmn.
Intended to run on Linux and other systems that have no OS at all.

Refer to README.md for more info.
*/


#ifdef WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <netdb.h>
#include <fcntl.h>

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#endif

#include "pcap.h"
#include "monocypher.h"
#include "common.h"

/* This implementation uses pcap but it is for portability and
 demo purpose.  On systems that are limited there may not be pcap.
 If the target system runs on custom environment with no OS or some
 realtime embedded kernel it will be necessary to have basic 
 adaptation layer that is capable of ethernet I/O.  You will
 need to replace pcap I/O with system specific read and write
 primitives that can get and send ethernet frames. Typically
 systems will have ethernet interface driver API that allows
 send and receiving ethernet frames. 
*/

unsigned char *my_macaddr;

/* bogus ID. We really need system-specific ID to 
 be retrieved from TPM or EEPROM or flash.  If the device lacks secure
 read-only ID uniquely encoded into device at manufacturing time
 that can later be read by software, we need to come up with 
 a software device ID which is stored remotely at the server.
 Depending on various meta data about the device, server side
 can look up software device ID that match the meta data such as
 device type, MAC address, etc.  That software ID will be
 generated remotely by server and kept there and device side agent
 client can retrieve that software ID from server.  This implementation
 does not do that. That code still needs to be written. */

int my_idval[] = {
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0
};

char *get_bogus_mac()
{				/* we do not use specific MAC address for now */
	static char dstaddr[6];
	dstaddr[0] = 0x00;
	dstaddr[1] = 0x60;
	dstaddr[2] = 0xe9;
	dstaddr[3] = 0xaa;
	dstaddr[4] = 0xbb;
	dstaddr[5] = 0xcc;

	return dstaddr;
}

char *get_bcast_mac()
{
	static char dstaddr[6];
	dstaddr[0] = 0xff;
	dstaddr[1] = 0xff;
	dstaddr[2] = 0xff;
	dstaddr[3] = 0xff;
	dstaddr[4] = 0xff;
	dstaddr[5] = 0xff;
	return dstaddr;
}

char hostname[200];		// XXX

char *get_host_name()
{
	// XXX a system specific way of getting host name or device name        
	gethostname(hostname, sizeof(hostname));
	return hostname;
}

/* Hello is first message. It sends public key and signature to the server side,
 unencrypted.  */
void fill_hello(char *buffer)
{
	crypto_ctx_t *cctx = get_my_cctx();
	fill_str(cctx);

	/* we don't do it yet but if unique ID is not available it could be
	   set to null and server side can fill it in for us as explained above. */
	sprintf(buffer, (char *)get_msg_template(), "hello", get_id_seq(),
		cctx->unique_id_str, cctx->signature_str,
		cctx->signature_public_key_str, cctx->public_key_str, "", "",
		"", "");
}


char *make_time_msg(char *tag, char *message, int mlen)
{
	time_t timer;
	time(&timer);
	struct tm *tm_info = localtime(&timer);
	char timebuf[26];
	strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	snprintf(message, mlen, "%s: The time is %s", tag, timebuf);
	return message;
}

int send_hello_packet()
{
	char packetbuf[1500];
	char *packet = &packetbuf[0];
	char *src_macaddr = get_bcast_mac();

	memset((void *)packet, 0, sizeof(packet));

	fill_ether_header(packet, (unsigned char *)my_macaddr,
			  (unsigned char *)src_macaddr);
	fill_hello(packet + 14);

	if (pcap_sendpacket
	    (get_adhandle(), (const u_char *)packet,
	     14 + strlen(packet + 14)) != 0) {
		printf("error: sending hello packet\n");
		return -1;
	}
	printf("sent HELLO packet %d, %s\n", strlen(packet + 14) + 14,
	       packet + 14); 
	return 1;
}

int handle_command(char *packet, char *peer_public_key, char *cmd,
		   device_info_t * di)
{
	char buffer[MAXLINE];
	memset(buffer, 0 , sizeof(buffer));
	memcpy(buffer, packet, 14);
	//printf("handle_command %s\n", cmd);

	/* commands are sent encrypted. Once decrpyted the command should 
	   look like CLI command.  Some commands can be interpreted directly
	   here, like "send xyz" kind of command.  Other commands can be
	   something that gets run as shell command using existing
	   utility programs that reside in the target device. For example,
	   a command could be "run ifconfig -a" then we run that on device
	   if the device has ifconfig command and return the output. 
	   This allows using external commands to accomplish most tasks.
	   Rather than expanding agent client program (this program) to
	   do extra work.  You also want to run external program because
	   you minimze crashes that can happen due to various features
	   that need to be activated when configuring the device. If the
	   configuration fails, agent must still continue, not crash. Only
	   external command may crash.  The external commands may be custom
	   made programs that accompany this agent program. Or they may
	   already exist in the system.  Or they may be downloaded via this agent
	   client.  To do that, we must support a command called "download" which
	   will download a new binary to be installed and runnable as CLI command
	   which can be run after being downloaded and installed on to the
	   device via the agent running on that device. This allows for
	   expanding agent capability in runtime and also ability to update
	   parts of agent features over time. */
	
	if (strcmp(cmd, "send hello") == 0) {
		return send_hello_packet();
	}

	if (strcmp(cmd, "send info") == 0) {
		char *msgtype = "info";
		char *extra = "extra info for bob is 123";
		
		/* send the message which will be encrypted and put into cipher_text */
		//printf("encrypt_send_packet msgtype %s message %s\n", msgtype, message);
		return encrypt_send_packet(buffer, peer_public_key,
						msgtype, "INFORMATION IS GOOD", extra);
	}			
	
	/* XXX here is where you can add more code to handle other commands */
	printf("error: unknown cmd %s\n", cmd);
	return -1;
}



int handle_msg(char *packet, device_info_t * di)
{
	message_t msg;
	char msgtype[MSLEN + 1];

	if (parse_msg(packet + 14, &msg) < 0) {
		printf("error: cannot parse message\n");
		return -3;
	}
	strcpy(msgtype, (const char *)msg.type);

	if (msg_type_check(msgtype) < 0) {
		printf("error: invalid msg type %s\n", msgtype);
		return -5;
	}
	// save our MAC address in the packet header
	fill_ether_header((char *)packet, (unsigned char *)di->macaddr,
			  (unsigned char *)&packet[6]);

	// presence of nonce or mac in the msg indicates encrypted content
	if (strlen((const char *)msg.nonce) <= 0) {
		/* printf("plain message text received type %s %s\n", msgtype,
		       msg.plain_text); */
		/* Should handle in handle_command(). */
		handle_command(packet, (char *)msg.public_key, msg.plain_text, di);

		
		return 1;
	}
	/* when we reach here we have encrypted msg so we must decrypt first */
	crypto_ctx_t *cctx = get_my_cctx();

	uint8_t peer_public_key[KSLEN];
	uint8_t mac[MAC_LEN];
	uint8_t nonce[NONCE_LEN];

	fromhex((char *)peer_public_key, KSLEN, 16, (char *)msg.public_key);
	fromhex((char *)mac, MAC_LEN, 16, (char *)msg.mac);
	fromhex((char *)nonce, NONCE_LEN, 16, (char *)msg.nonce);

	uint8_t shared_secret[KSLEN];
	memset((void *)shared_secret, 0, sizeof(shared_secret));
	crypto_x25519(shared_secret, cctx->secret_key, peer_public_key);
	/* we skipped validating the signature but we should do it really 
	   call verify_signature() */
	uint8_t shared_secret_str[SLEN];
	memset((void *)shared_secret_str, 0, sizeof(shared_secret_str));
	tohex((char *)shared_secret, KSLEN, 16, (char *)shared_secret_str);

	//printf("agclient: decrypting with shared_secret %s peer_pub %s\n", shared_secret_str, msg.public_key);

	char cipher_text[MSLEN + 1], plain_text[MSLEN + 1];

	memset((void *)cipher_text, 0, sizeof(cipher_text));
	memset((void *)plain_text, 0, sizeof(plain_text));
	fromhex((char *)cipher_text, MSLEN, 16, (char *)msg.cipher_text);

	if (crypto_unlock
	    ((uint8_t *) plain_text, shared_secret, nonce, mac,
	     (uint8_t *) cipher_text, strlen(cipher_text))) {
		printf("error: cannot decrypt\n");
		return -9;
	}
	printf("agclient decrypted: %s\n", plain_text);
	
	// handle decrypted msg and send packet reply
	handle_command(packet, (char *)msg.public_key, plain_text, di);
	return 1;
}

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data)
{
	const u_char *message;
	u_char packet[1500];
	int i;
	device_info_t *di = (device_info_t *) param;
	// we are called here each time a packet is received by pcap
	message = pkt_data + 14;
	if (pkt_data[12] != 0xda || pkt_data[13] != 0xda)
		return;

	//printf("incoming packet %s\n", message);

	int mlen = strlen((const char *)message);
	if (mlen < MINMSG || mlen >= MAXLINE) {
		printf("error: agclient bad size %d\n", mlen);
		return;
	}
	memset((void *)packet, 0, sizeof(packet));
	strcpy((char *)(packet + 14), (const char *)message);
	if (handle_msg((char *)packet, di) < 0) {
		printf("error: failed to handle msg\n");
		return;
	}
}

void print_help(char *name)
{
	printf("Usage: %s flags\n", name);
	printf("-h print help\n");
	printf("-l list network interfaces\n");
	printf("-d index specify network interface index\n");
	
	fflush(stdout);
	fexit(1);
}

int main(int argc, char *argv[])
{
	int list_ifs = 0;
	int devnum = -1;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "-h") == 0) {
			print_help(argv[0]);
		} else if (strcmp(argv[i], "-l") == 0) {
			list_ifs = 1;
		} else if (strcmp(argv[i], "-d") == 0) {
			if (++i < argc)
				devnum = atoi(argv[i]);
			else
				print_help(argv[0]);
		} else {
			print_help(argv[0]);
		}
		i++;
	}

	init_my_cctx(my_idval, sizeof(my_idval) / sizeof(int));
	pcap_if_t *adevs;

	adevs = init_alldevs();
	if (!adevs) {
		printf("error: cannot list network devices\n");
		fexit(1);
	}
	if (get_num_devices() < 1) {
		printf("error: no network devices\n");
		fexit(1);
	}
	if (list_ifs) {
		list_devs(adevs);
		return 0;
	}
	if (devnum < 0) {
		printf("Choose the network device from the list, use -d\n");
		printf("To list network devices use -l\n");
		fexit(1);
	}
	if (devnum >= get_num_devices()) {
		printf("error: network device index %d out of range\n", devnum);
		fexit(1);
	}

	pcap_if_t *d;

	for (d = adevs, i = 0; i != devnum && d; d = d->next, i++) ;

	pcap_t *adh;
	adh = pcap_dev_setup(d);
	if (!adh) {
		printf("error: cannot setup pcap device %s\n", d->name);
		fexit(1);
	}
	my_macaddr = (unsigned char *)getmac(d->name);

	if (send_hello_packet() < 0) {
		printf("error: cannot send hello packet\n");
		fexit(1);
	}

	char *host = get_host_name();

	device_info_t di;
	di.d = d;
	di.macaddr = my_macaddr;
	di.host = host;
	pcap_loop(adh, 0, packet_handler, (unsigned char *)&di);

	//pcap_freealldevs(alldevs);
	//pcap_close(adhandle);

	return 0;
}
