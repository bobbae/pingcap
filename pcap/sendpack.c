#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>


int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[1460];
	int i;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;

	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	printf("list all devs\n");	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	printf("number of interfaces: %d\n",i);
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	
	/* if (argc != 2)
	{
		printf("usage: %s interface", argv[0]);
		return 1;
	}
    
	if ((fp = pcap_open_live(argv[1], 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 2;
	}
	*/

	printf("Opening device %s\n", d->name);

	/* Open the adapter */
	if ((fp= pcap_open_live(d->name,	// name of the device
			 65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
			 1,			// promiscuous mode (nonzero means promiscuous)
			 1000,			// read timeout
			 errbuf			// error buffer
		 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(fp) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
	packet[0]=1;
	packet[1]=1;
	packet[2]=1;
	packet[3]=1;
	packet[4]=1;
	packet[5]=1;
	
	/* set mac source to 2:2:2:2:2:2 */
	packet[6]=0x34;
	packet[7]=0x29;
	packet[8]=0x8f;
	packet[9]=0x90;
	packet[10]=0x88;
	packet[11]=0x81;
	
	/* ethernet type */
	packet[12]=0xaa;
	packet[13]=0xaa;

	/* Fill the rest of the packet */
	for(i=14;i<100;i++)
	{
		packet[i]= (u_char)i;
	}

	while (1) {
		printf("sending\n");

		/* Send down the packet */
		if (pcap_sendpacket(fp,	// Adapter
			packet,				// buffer with the packet
			200					// size
			) != 0)
		{
			printf("\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}
		printf("sent\n");

		sleep(3);
	}
	pcap_close(fp);	
	return 0;
}

