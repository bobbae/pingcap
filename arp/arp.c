#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define PROTOCOL_TYPE 0x800
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

struct arp_header
{
        unsigned short hardware_type;
        unsigned short protocol_type;
        unsigned char hardware_len;
        unsigned char  protocol_len;
        unsigned short opcode;
        unsigned char sender_mac[MAC_LENGTH];
        unsigned char sender_ip[IPV4_LENGTH];
        unsigned char target_mac[MAC_LENGTH];
        unsigned char target_ip[IPV4_LENGTH];
};

int main(int argc,char * argv[])
{
        int sd;
        unsigned char buffer[BUF_SIZE];
        unsigned char source_ip[4] = {10,222,190,160};
        unsigned char target_ip[4] = {10,222,190,139};
        struct ifreq ifr;
        struct ethhdr *send_req = (struct ethhdr *)buffer;
        struct ethhdr *rcv_resp= (struct ethhdr *)buffer;
        struct arp_header *arp_req = (struct arp_header *)(buffer+ETH2_HEADER_LEN);
        struct arp_header *arp_resp = (struct arp_header *)(buffer+ETH2_HEADER_LEN);
        struct sockaddr_ll socket_address;
        int index,ret,length=0,ifindex;
	char *interface;

	if (argc < 2) {
		printf("Usage: %s interface\n", argv[0]);
		exit(1);
	}
        memset(buffer,0x00,60);
        /*open socket*/
        sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sd == -1) {
                perror("socket():");
                exit(1);
        }

	interface = argv[1];
	printf("using interface %s\n",interface);
        strcpy(ifr.ifr_name, interface);
        /*retrieve ethernet interface index*/
        if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
                perror("SIOCGIFINDEX");
                exit(1);
        }
        ifindex = ifr.ifr_ifindex;
        printf("interface index is %d\n",ifindex);

        /*retrieve corresponding MAC*/
        if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
                perror("SIOCGIFINDEX");
                exit(1);
        }
        close (sd);

        for (index = 0; index < 6; index++)
        {

                send_req->h_dest[index] = (unsigned char)0xff;
                arp_req->target_mac[index] = (unsigned char)0x00;
                /* Filling the source  mac address in the header*/
                send_req->h_source[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
                arp_req->sender_mac[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
                socket_address.sll_addr[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
        }
        printf("Successfully got eth1 MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        send_req->h_source[0],send_req->h_source[1],send_req->h_source[2],
                        send_req->h_source[3],send_req->h_source[4],send_req->h_source[5]);
        printf(" arp_reqMAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        arp_req->sender_mac[0],arp_req->sender_mac[1],arp_req->sender_mac[2],
                        arp_req->sender_mac[3],arp_req->sender_mac[4],arp_req->sender_mac[5]);
        printf("socket_address MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        socket_address.sll_addr[0],socket_address.sll_addr[1],socket_address.sll_addr[2],
                        socket_address.sll_addr[3],socket_address.sll_addr[4],socket_address.sll_addr[5]);

        /*prepare sockaddr_ll*/
        socket_address.sll_family = AF_PACKET;
        socket_address.sll_protocol = htons(ETH_P_ARP);
        socket_address.sll_ifindex = ifindex;
        socket_address.sll_hatype = htons(ARPHRD_ETHER);
        socket_address.sll_pkttype = (PACKET_BROADCAST);
        socket_address.sll_halen = MAC_LENGTH;
        socket_address.sll_addr[6] = 0x00;
        socket_address.sll_addr[7] = 0x00;

        /* Setting protocol of the packet */
        send_req->h_proto = htons(ETH_P_ARP);

        /* Creating ARP request */
        arp_req->hardware_type = htons(HW_TYPE);
        arp_req->protocol_type = htons(ETH_P_IP);
        arp_req->hardware_len = MAC_LENGTH;
        arp_req->protocol_len =IPV4_LENGTH;
        arp_req->opcode = htons(ARP_REQUEST);
        for(index=0;index<5;index++)
        {
                arp_req->sender_ip[index]=(unsigned char)source_ip[index];
                arp_req->target_ip[index]=(unsigned char)target_ip[index];
        }
        // Submit request for a raw socket descriptor.
        if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
                perror ("socket() failed ");
                exit (EXIT_FAILURE);
        }

        buffer[32]=0x00;
        ret = sendto(sd, buffer, 42, 0, (struct  sockaddr*)&socket_address, sizeof(socket_address));
        if (ret == -1)
        {
                perror("sendto():");
                exit(1);
        }
        else
        {
                printf(" Sent the ARP REQ \n\t");
                for(index=0;index<42;index++)
                {
                        printf("%02X ",buffer[index]);
                        if(index % 16 ==0 && index !=0)
                        {printf("\n\t");}
                }
        }
        printf("\n\t");
        memset(buffer,0x00,60);
        while(1)
        {
                length = recvfrom(sd, buffer, BUF_SIZE, 0, NULL, NULL);
                if (length == -1)
                {
                        perror("recvfrom():");
                        exit(1);
                }
                if(htons(rcv_resp->h_proto) == PROTO_ARP)
                {
                        //if( arp_resp->opcode == ARP_REPLY )
                        printf(" RECEIVED ARP RESP len=%d \n",length);
                        printf(" Sender IP :");
                        for(index=0;index<4;index++)
                                printf("%u.",(unsigned int)arp_resp->sender_ip[index]);

                        printf("\n Sender MAC :");
                        for(index=0;index<6;index++)
                                printf(" %02X:",arp_resp->sender_mac[index]);

                        printf("\nReceiver  IP :");
                        for(index=0;index<4;index++)
                                printf(" %u.",arp_resp->target_ip[index]);

                        printf("\n Self MAC :");
                        for(index=0;index<6;index++)
                                printf(" %02X:",arp_resp->target_mac[index]);

                        printf("\n  :");

                        break;
                }
        }

        return 0;
}
