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
#include <time.h>

int SEQ = 0;
unsigned long send_seq, ack_seq, srcport;
unsigned long srcport;
int rsock, ssock;
int *seq_num = 0;
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
	char *data = "GET http://detectportal.firefox.com/success.txt HTTP/1.1\r\nHost: 192.168.168.232\r\n\r\n";
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

unsigned long spoof_nack(unsigned long my_ip, unsigned long their_ip, unsigned short port)
{
    struct iphdr ih;
    struct tcphdr th;
    char buf[1024];
    struct timeval tv;
    char *data = "";

    ih.version=4;
    ih.ihl=5;
    ih.tos=0;           /* XXX is this normal? */
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

unsigned long getLocalIP(char *ifname)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct ifreq ifr;
    unsigned long tmp;

    if (strlen(ifname) < IFNAMSIZ)
    {
        strcpy(ifr.ifr_name, ifname);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
            perror("ioctl");
            exit(-1);
        }
    }
    else
    {
        perror("invalid ifname");
        exit(-1);
    }
    memcpy(&tmp, &(ifr.ifr_addr), sizeof(tmp));
    tmp >>= 32;

    close(sock);
    sock = 0;
    return tmp;
}

int main(int argc, char **argv)
{
    int i;
    unsigned long des_ip, src_ip;
    unsigned long src_port, des_port;
    char buf[1024];
	char vbuf[0x800];
	ssize_t msg_len = 0;
	const char *ifname = "ens33";
	char tmp[4];
	system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP -s 192.168.168.232 -d 192.168.168.69");
	system("iptables -L");
	socklen_t socklen = 0;
    src_ip = getLocalIP(ifname);
    des_ip=getaddr("192.168.168.69");
//	des_ip=getaddr("140.115.59.5");
    src_port=atoi("80");
    des_port=atoi("3128");
	setvbuf(stdin, vbuf, _IONBF, 0);
	setvbuf(stdout, vbuf, _IONBF, 0);
	setvbuf(stderr, vbuf, _IONBF, 0);
	srcport = src_port;
	srand(time(NULL));
	SEQ = rand();
	printf("init seq num = 0x%08x\n", SEQ);


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
	spoof_open(src_ip, des_ip, des_port);

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

	spoof_data(src_ip, des_ip, des_port);
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
	if((msg_len = recv(rsock, buf, 0x3b - 0x0e, 0)) == -1)
    {
        perror("recv: ");
        exit(-1);
    }

	spoof_nack(src_ip, des_ip, des_port);
	close(ssock);
	close(rsock);
	system("iptables -D OUTPUT 1");
    return 0;
}
