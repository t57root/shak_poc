#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct psd_tcp
{
	u_int32_t saddr;
	u_int32_t daddr;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr tcp;
	char options[20];
};

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_tcp buf;
	memset(&buf, 0, sizeof(buf));
	u_short ans;
	buf.saddr = src;
	buf.daddr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(len);
	memcpy(&(buf.tcp), addr, len);
	ans = in_cksum((unsigned short *)&buf, 12 + len);
	return (ans);
}
 


int main(int argc, char **argv)
{
	int n, sockfd, port;
	struct iphdr* iph;
	struct tcphdr* th;
	struct sockaddr_in dest;
	char *options = "\x02\x04\x05\xb4\x04\x02\x08\x0a\x00\x1b\xd9\xea\x00\x00\x00\x00\x01\x03\x03\x06";
	char *dest_addr;

	if(argc != 3){
		printf("Invalid parameter");
		return -1;
	}
	dest_addr = argv[1];
	port = atoi(argv[2]);
	  
	char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)+20];
	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr)+20);
		   
	iph = (struct iphdr*) packet;  
	th = (struct tcphdr*) (packet + sizeof(struct iphdr));  
	  
	iph->ihl              = 5;  
	iph->version       = 4;  
	iph->tos             = 0;  
	iph->tot_len        = sizeof(struct iphdr) + sizeof(struct tcphdr)+20;
	iph->id               = htons(0xc757);	// xFlag
	iph->ttl               = 64;
	iph->protocol     = IPPROTO_TCP;
	iph->frag_off = htons(0x02 << 13);
	iph->saddr         = inet_addr("192.168.4.101");  
	iph->daddr         = inet_addr(dest_addr);  
	iph->check = 0;
	  
	th->dest = htons(port);
	th->source = htons(0x679);		// xFlag
	th->seq = htons(0xc757);		// xFlag_tcp
	th->ack_seq = 0;
	th->res2 = 0;
	th->doff = (sizeof(struct tcphdr) + 20) / 4; 
	th->syn = 1;
	th->window = htons(14600);		//xFlag_ XXX
	th->urg_ptr = 0;    
	th->check = in_cksum_tcp(iph->saddr, iph->daddr, (unsigned short *) th, sizeof(struct tcphdr) + 20);
	memcpy(packet+sizeof(struct iphdr) + sizeof(struct tcphdr), options, 20);

	if( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
	    perror("socket() error");
	    return -1;
	}
	n = 1;  
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const int *)&n, sizeof(n)) < 0){  
	    perror("setsockopt() error");
	    return -1;
	}

	dest.sin_family = AF_INET;  
	dest.sin_addr.s_addr = inet_addr(dest_addr);  
		   
	if((n = sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr))) < 0){ 
	    printf("sendto() error");
	    return -1;
	}
	return 0;
}
