#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define BUF_SIZE 2048


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


// Function to caluclate packet checksum. Taken from BSD 
unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}


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
	printf("RAW PACKET SENT\n");
	close(sock);
}



int main()
{
	char buf[BUF_SIZE];
	memset(buf, 0, BUF_SIZE);
	
	// Generate ICMP packet
	struct icmpheader *icmp_header = (struct icmpheader *) (buf + sizeof(struct ipheader));
	icmp_header->type = 8; // Set icmp type 8 as echo request
	icmp_header->checksum = 0;
	icmp_header->checksum = in_cksum((unsigned short *)icmp_header, sizeof(struct icmpheader));

	
	// Generate the IP header
	struct ipheader *ip_packet = (struct ipheader *)buf;
	ip_packet->ip_v = 4;
	ip_packet->ip_hl = 5;
	ip_packet->ip_ttl = 64;
	ip_packet->destination_ip.s_addr = inet_addr("8.8.8.8");
	ip_packet->ip_protocol = IPPROTO_ICMP;
	ip_packet->ip_len=htons(sizeof(struct ipheader) + sizeof(struct icmpheader));


	send_packet(ip_packet);
	return 0;
}
