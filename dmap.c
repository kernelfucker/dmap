/* See LICENSE file for license details */
/* dmap - dynamic minimal network mapper */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define max_ips 8192
#define max_ports 65535
#define scan_ping 0
#define scan_connect 1
#define scan_sync 2

#define last_version 0.2

const int af = AF_INET;
const int sr = SOCK_RAW;
const int ss = SOL_SOCKET;
const int sv = SO_RCVTIMEO;
const int id = INET_ADDRSTRLEN;
const int im = ICMP_ECHO;
const int ic = IPPROTO_ICMP;
const int it = IPPROTO_TCP;
const int ii = IPPROTO_IP;
const int ir = IP_HDRINCL;

struct scanc{
	struct in_addr ips[max_ips];
	int ipcn;
	uint16_t ports[max_ports];
	int portcn;
	int type;
};

static void usage(const char *s){
	fputs("dmap - dynamic minimal network mapper\n", stderr);
	fprintf(stderr, "usage: %s -i <ip> -p <ports> -t <types>\n", s);
	fputs("  -i  ip range (example: 192.168.1.0/28)\n", stderr);
	fputs("  -p  ports (example: 21,22,53,80)\n", stderr);
	fputs("  -t  scan type: ping, connect, sync\n", stderr);
	fputs("  -h  display this\n", stderr);
	fputs("  -v  show version information\n", stderr);
	exit(1);
}

static void parse_ps(const char *s, struct scanc *cf){
	const char *p = s;
	while(*p && cf->portcn < max_ports){
		cf->ports[cf->portcn++] = strtoul(p, (char**)&p, 10);
		if(*p == ',') p++;
	}
}

static void parse_ip(const char *in_ip, struct scanc *cf){
	char ip[32];
	char *slash;
	int bits, i;
	struct in_addr base, tmp;
	uint32_t mask, net;
	strncpy(ip, in_ip, sizeof(ip) - 1);
	ip[sizeof(ip) - 1] = '\0';
	slash = strchr(ip, '/');
	if(!slash)
		usage("dmap");
	*slash = '\0';
	bits = atoi(slash + 1);
	if(bits < 0 || bits > 32)
		usage("dmap");
	if(inet_aton(ip, &base) == 0)
		usage("dmap");

	mask = 0xFFFFFFFF << (32 - bits);
	net = ntohl(base.s_addr) & mask;
	for(i = 0; i < (1 << (32 - bits)) && cf->ipcn < max_ips; i++){
		tmp.s_addr = htonl(net + i);
		cf->ips[cf->ipcn++] = tmp;
	}
}

static int parse_tp(const char *s){
	if(!strcmp(s, "ping")) return scan_ping;
	if(!strcmp(s, "connect")) return scan_connect;
	if(!strcmp(s, "sync")) return scan_sync;
	usage("dmap");
	return scan_ping;
}

static uint16_t icmp_ck(void *vd, size_t length){
	uint32_t sum = 0;
	uint16_t *d = vd;
	for(; length > 1; length -= 2)
		sum += *d++;
	if(length == 1)
		sum += *(uint8_t *)d;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static void scanp(struct scanc *cf){
	int socketl = socket(af, sr, ic);
	if(socketl < 0){
		perror("socket");
		exit(1);
	}

	struct timeval timeout = {1, 0};
	setsockopt(socketl, ss, sv, &timeout, sizeof(timeout));
	for(int i = 0; i < cf->ipcn; i++){
		struct sockaddr_in target = {0};
		target.sin_family = af;
		target.sin_addr = cf->ips[i];

		char ipstr[id];
		inet_ntop(af, &cf->ips[i], ipstr, sizeof(ipstr));

		uint8_t packet[64] = {0};
		struct icmphdr *icmp = (struct icmphdr *)packet;
		icmp->type = im;
		icmp->code = 0;
		icmp->un.echo.id = htons(1024);
		icmp->un.echo.sequence = htons(i);
		icmp->checksum = icmp_ck(packet, sizeof(packet));
		if(sendto(socketl, packet, sizeof(packet), 0,
			(struct sockaddr *)&target, sizeof(target)) < 0){
		fprintf(stderr, "sendto %s: %s\n", ipstr, strerror(errno));
		continue;
		}

		uint8_t buf[1024];
		struct sockaddr_in src;
		socklen_t srclen = sizeof(src);
		ssize_t len = recvfrom(socketl, buf, sizeof(buf), 0,
			(struct sockaddr *)&src, &srclen);
		if(len > 0){
			printf("%s is up\n", ipstr);
		} else {
			printf("%s is down\n", ipstr);
		}
	}

	close(socketl);

}

void scan_connect_fc(struct scanc *cf){
	for(int i = 0; i < cf->ipcn; i++){
		struct sockaddr_in addr = {0};
		addr.sin_family = af;
		addr.sin_addr = cf->ips[i];
		char ipstr[id];
		inet_ntop(af, &cf->ips[i], ipstr, sizeof(ipstr));
		for(int h = 0; h < cf->portcn; h++){
			addr.sin_port = htons(cf->ports[h]);
			int socketl = socket(af, ss, 0);
			if(socketl < 0){
				perror("socket");
				continue;
			}

			struct timeval timeout = {1, 0};
			setsockopt(socketl, ss, sv, &timeout, sizeof(timeout));
			int rs = connect(socketl, (struct sockaddr *)&addr, sizeof(addr));
			if(rs == 0){
				printf("%s:%d is open\n", ipstr, cf->ports[h]);
			} else {
				printf("%s:%d is closed\n", ipstr, cf->ports[h]);
			}

			close(socketl);
		}
	}
}

struct ph{
	uint32_t src;
	uint32_t dst;
	uint8_t zero;
	uint8_t protocol;
	uint16_t len;
};

static uint16_t tcpck(struct iphdr *iph, struct tcphdr *tcph, int len){
	struct ph ph;
	ph.src = iph->saddr;
	ph.dst = iph->daddr;
	ph.zero = 0;
	ph.protocol = it;
	ph.len = htons(len);

	uint32_t sum = 0;
	uint16_t *p = (uint16_t *)&ph;
	for(int i = 0; i < sizeof(ph)/2; i++) sum += *p++;

	p = (uint16_t *)tcph;

	for(int i = 0; i < len/2; i++) sum += *p++;
	if(len % 2) sum += *((uint8_t *)p);	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return ~sum;
}

void scan_sync_fc(struct scanc *cf){
	int socketl = socket(af, sr, it);
	if(socketl < 0){
		perror("socket");
		exit(1);
	}

	int one = 1;
	if(setsockopt(socketl, ii, ir, &one, sizeof(one)) < 0){
		perror("setsockopt");
		exit(1);
	}

	char buffer[4096];
	struct iphdr *iph = (struct iphdr *)buffer;
	struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
	for(int i = 0; i < cf->ipcn; i++){
		for(int h = 0; h < cf->portcn; h++){
			memset(buffer, 0, sizeof(buffer));
			struct sockaddr_in target = {0};
			target.sin_family = af;
			target.sin_addr = cf->ips[i];
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0;
			iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
			iph->id = htons(54321);
			iph->frag_off = 0;
			iph->ttl = 64;
			iph->protocol = it;
			iph->check = 0;
			iph->saddr = inet_addr("127.0.0.1");
			iph->daddr = cf->ips[i].s_addr;
			iph->check = icmp_ck((void *)iph, sizeof(struct iphdr));

			tcph->source = htons(65535);
			tcph->dest = htons(cf->ports[h]);
			tcph->seq = htonl(0);
			tcph->ack_seq = 0;
			tcph->doff = 5;
			tcph->syn = 1;
			tcph->window = htons(1024);
			tcph->check = 0;
			tcph->urg_ptr = 0;
			tcph->check = tcpck(iph, tcph, sizeof(struct tcphdr));

			if(sendto(socketl, buffer, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
				(struct sockaddr *)&target, sizeof(target)) < 0){
				perror("sendto");
				continue;
			}

			uint8_t rbuf[1024];
			struct sockaddr_in src;
			socklen_t slen = sizeof(src);
			struct timeval tval = {1, 0};
			setsockopt(socketl, ss, sv, &tval, sizeof(tval));
			ssize_t rlen = recvfrom(socketl, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &slen);
			if(rlen > 0){
				struct iphdr *iphr = (struct iphdr *)rbuf;
				if(iphr->protocol == it){
					struct tcphdr *rtcp = (struct tcphdr *)(rbuf + iphr->ihl*4);
					if(rtcp->source == htons(cf->ports[h])){
					if(rtcp->syn && rtcp->ack){
						char ipstr[id];
						inet_ntop(af, &cf->ips[i], ipstr, sizeof(ipstr));
						printf("%s:%d is open\n", ipstr, cf->ports[h]);
					}
				}
			}
		}
	}
}

close(socketl);

}

int main(int argc, char **argv){
	struct scanc cf = {0};
	int optl;
	char *iparg = NULL, *parg = NULL, *targ = NULL;
	while((optl = getopt(argc, argv, "i:p:t:hv")) != -1){
		switch(optl){
		case 'i': iparg = optarg; break;
		case 'p': parg = optarg; break;
		case 't': targ = optarg; break;
		case 'h': usage(argv[0]); break;
		case 'v':
			printf("dmap-%s\n", last_version);
			exit(0);
			break;
		default: usage(argv[0]);
		}
	}

	if(!iparg || !parg || !targ)
		usage(argv[0]);

	parse_ip(iparg, &cf);
	parse_ps(parg, &cf);
	cf.type = parse_tp(targ);
	switch(cf.type){
	case scan_ping:
		scanp(&cf);
		break;
	case scan_connect:
		scan_connect_fc(&cf);
		break;
	case scan_sync:
		scan_sync_fc(&cf);
		break;
	}

	return 0;
}
