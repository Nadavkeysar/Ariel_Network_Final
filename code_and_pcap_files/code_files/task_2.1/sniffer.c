#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>



// define IP struct
struct ipheader 
{
	// setting the IP header fields
	unsigned char ip_hl: 4; //Extract needed bits
	unsigned char ip_v: 4; //Extract needed bits
	unsigned char ip_tos;
	unsigned short int ip_len;
	unsigned short int ip_id;
	unsigned short int ip_flag: 3; //Extract needed bits
	unsigned short int ip_off: 13; //Extract needed bits
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short int ip_checksum;
	struct in_addr source_ip;
	struct in_addr destination_ip;
};


// define etherent struct
struct ethheader 
{
	u_char ether_dhost [6];
	u_char ether_shost [6];
	u_short ether_type;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	// Creating the ethheader object from the packet;
	struct ethheader *ethernet_packet = (struct ethheader*)packet;
	if (ntohs(ethernet_packet->ether_type) == 0x0800) //checking if EtherType is 0x0800 which is IPv4
	{
		struct ipheader *ip_packet = (struct ipheader*)(packet + sizeof(struct ethheader));
		printf("Packet sent from %s to", inet_ntoa(ip_packet->source_ip));
		printf(" %s\n", inet_ntoa(ip_packet->destination_ip));
	}
}


int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL)
	{
		printf("Error in pacp_open_live. exiting.\n");
		return -1;
	}

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}
