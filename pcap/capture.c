#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <time.h>

#include "pcap.h"

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

typedef struct ip_header {
	u_char ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char tos;		// Type of service 
	u_short tlen;		// Total length 
	u_short identification;	// Identification
	u_short flags_fo;	// Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl;		// Time to live
	u_char proto;		// Protocol
	u_short crc;		// Header checksum
	ip_address saddr;	// Source address
	ip_address daddr;	// Destination address
	u_int op_pad;		// Option + Padding
} ip_header;

typedef struct udp_header {
	u_short sport;		// Source port
	u_short dport;		// Destination port
	u_short len;		// Datagram length
	u_short crc;		// Checksum
} udp_header;

typedef struct ethernet_header {
	u_char dst[6];		// Destination host address
	u_char src[6];		// Source host address
	u_short type;		// IP? ARP? RARP? etc
} ethernet_header;

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data);

pcap_t *adhandle;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *paddr;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	//char packet_filter[] = "ip and udp";
	char packet_filter[] = "ether proto 0xaaaa or udp";	
	//char packet_filter[] = "ether proto 0xaaaa";
	struct bpf_program fcode;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("starting\n");

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	printf("list all devs\n");
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)", d->description);
		else
			printf(" (No description available)");
		if (d->addresses && d->addresses->addr) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)d->addresses->addr;
			printf(" addr: %s", inet_ntoa(sin->sin_addr));
		}
		printf("\n");
	}
	printf("number of interfaces: %d\n", i);
	if (i == 0) {
		printf
		    ("\nNo interfaces found! Make sure Pcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i) {
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++) ;

	printf("Opening device %s\n", d->name);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
				       65536,	// 65536 grants that the whole packet will be captured on all the MACs.
				       1,	// promiscuous mode (nonzero means promiscuous)
				       1000,	// read timeout
				       errbuf	// error buffer
	     )) == NULL) {
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Pcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr,
			"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	netmask = 0xffffff;
#if 0
	if (d->addresses != NULL)
		netmask =
		    ((struct sockaddr_in *)(d->addresses->netmask))->
		    sin_addr.S_un.S_addr;
#endif

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->name);

	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char * param, const struct pcap_pkthdr *header,
		    const u_char * pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ethernet_header *eth_hdr;
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	u_char *outpkt;
	time_t now;
	char ctimestr[200];
	int i;

	//local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	time(&now);
	strcpy(ctimestr, ctime(&now));
	i = strlen(ctimestr);
	ctimestr[i - 1] = '\0';

	printf("%s len %d ", ctimestr, header->len);

	eth_hdr = (ethernet_header *) pkt_data;
	printf("[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x (%x)] ",
	       eth_hdr->src[0], eth_hdr->src[1], eth_hdr->src[2],
	       eth_hdr->src[3], eth_hdr->src[4], eth_hdr->src[5],
	       eth_hdr->dst[0], eth_hdr->dst[1], eth_hdr->dst[2],
	       eth_hdr->dst[3], eth_hdr->dst[4], eth_hdr->dst[5],
	       eth_hdr->type);
	ih = (ip_header *) (pkt_data + 14);	//length of ethernet header

	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char *) ih + ip_len);

	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
	       ih->saddr.byte1,
	       ih->saddr.byte2,
	       ih->saddr.byte3,
	       ih->saddr.byte4,
	       sport,
	       ih->daddr.byte1,
	       ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);

	/*
	   if (pcap_sendpacket(adhandle, pkt_data, header->len) != 0) {
	   printf("Error sending packet: %s\n", pcap_geterr(adhandle));
	   return;
	   }

	   outpkt = (u_char *)pkt_data;
	   outpkt[0] = pkt_data[6];
	   outpkt[1] = pkt_data[7];
	   outpkt[2] = pkt_data[8];
	   outpkt[3] = pkt_data[9];
	   outpkt[4] = pkt_data[10];
	   outpkt[5] = pkt_data[11];
	   printf("sent back to %x:%x:%x:%x:%x:%x\n",
	   outpkt[0], outpkt[1], outpkt[2], outpkt[3], outpkt[4], outpkt[5]);
	 */
}
