#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pcap.h>


#define BUF_SIZE 512


// define ICMP struct
struct icmpheader 
{
	unsigned char type;
	unsigned char code;
	unsigned short int checksum;
	unsigned short int id; 
	unsigned short int seq;
};


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


void send_packet(struct ipheader* ip_packet)
{
	// Construct  the packet
	struct sockaddr_in sockaddr;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
	{
		printf("ERROR while creating socket.Exiting!\n");
		return;
	}
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr = ip_packet->destination_ip;

	// Send the packet
	sendto(sock, ip_packet, ntohs(ip_packet->ip_len), 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	printf("Forged ICMP packet sent\n");
	close(sock);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	// Creating the ethheader object from the packet;
	struct ethheader *ethernet_packet = (struct ethheader*)packet;
	if (ntohs(ethernet_packet->ether_type) == 0x0800) //checking if EtherType is 0x0800 which is IPv4
	{
		struct ipheader *ip_packet = (struct ipheader*)(packet + sizeof(struct ethheader));
		if (ip_packet->ip_protocol == IPPROTO_ICMP)
		{
			printf("Found incoming ICMP packet:\n");
			char buf[BUF_SIZE];
			// Copy the incoming packet to our buf
			memset((char*)buf, 0, BUF_SIZE);
			memcpy((char*)buf, ip_packet, ntohs(ip_packet->ip_len));
			struct ipheader* forged_ip_packet = (struct ipheader*)buf;
			struct icmpheader* forged_icmp_packet = (struct icmpheader*)(buf + (ip_packet->ip_hl * 4));

			// Send out the reply as the actual destination of the ICMP packet.
			forged_ip_packet->destination_ip = ip_packet->source_ip;
			forged_ip_packet->source_ip = ip_packet->destination_ip;
			forged_ip_packet->ip_ttl = 64;
			// Setting ICMP type as 0 (Echo Reply). https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
			forged_icmp_packet->type = 0;
			send_packet(forged_ip_packet);
		}
	}	
}



int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp[icmptype] = icmp-echo"; // Filter only ICMP echo request packets.
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 
	if (handle == NULL)
	{
		printf("Error in pacp_open_live. exiting.\n");
		return -1;
	}

	pcap_compile(handle, &fp, filter_exp, 0, net);      
	pcap_setfilter(handle, &fp);                             
	pcap_loop(handle, -1, got_packet, NULL);                
	pcap_close(handle);  

	return 0;
}
