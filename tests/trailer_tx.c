// SPDX-License-Identifier: GPL-2.0

/* Send a UDP packet with an Ethernet trailer with timestamp.
 *
 * Support three formats inserted by switches:
 * metamako/cpacket, cisco ttag and broadcom.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef int(*trailer_fn)(void *, struct timespec *);

static struct sockaddr_in saddr4, daddr4;
static struct sockaddr_in6 saddr6, daddr6;

static int cfg_family;
static uint16_t cfg_family_eth;
static int cfg_ifindex;
static char cfg_mac_dst[ETH_ALEN];
static unsigned int cfg_num_pkt = 1;
static const int cfg_payload_len = 100;
static trailer_fn cfg_trailer_fn;

/* cpacket format
 *
 * https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ixiatrailer.c
 */
struct trailer_cpacket {
	uint32_t secs;
	uint32_t nsecs;
	uint8_t flags;
	uint16_t device_id;
	uint8_t port_id;
} __attribute__((packed));

/* cisco ttag format
 *
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-cisco-ttag.c
 */
struct trailer_ttag {
	uint8_t ts[6];	/* 48b nsec */
};

/* broadcom format */
struct trailer_brcm {
	uint8_t ts[6];      /* 48b timestamp: 18b sec + 30b nsec */
	uint8_t reserved;
	uint8_t origin[3];
} __attribute__((packed));

/* analogue to sockaddr_storage */
union trailer_storage {
	struct trailer_cpacket cpacket;
	struct trailer_ttag ttag;
	struct trailer_brcm brcm;
};

union ip_storage {
	struct iphdr ip4;
	struct ipv6hdr ip6;
};

static uint16_t csum_fold16(unsigned long sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static uint16_t get_ip_csum(const uint16_t *start, int num_words,
			    unsigned long sum)
{
	int i;

	for (i = 0; i < num_words; i++)
		sum += start[i];

	return csum_fold16(sum);
}

static void fill_udp_csum(struct udphdr *udph,
			  const void *addrs, unsigned int alen,
			  const void *payload, unsigned int plen)
{
	unsigned long sum;
	int i;

	sum = htons(IPPROTO_UDP);
	sum += udph->len;

	/* sum over two addresses, length in halfwords */
	for (i = 0; i < alen; i++)
		sum += ((uint16_t *)addrs)[i];

	for (i = 0; i < sizeof(*udph) >> 1; i++)
		sum += ((uint16_t *)udph)[i];

	for (i = 0; i < cfg_payload_len >> 1; i++)
		sum += ((uint16_t *)payload)[i];

	udph->check = csum_fold16(sum);
}

static int fill_ip4(void *_ip)
{
	struct iphdr *ip4 = _ip;

	ip4->ihl = 5;
	ip4->version = 4;
	ip4->tot_len = htons(sizeof(*ip4) + sizeof(struct udphdr) + cfg_payload_len);
	ip4->protocol = IPPROTO_UDP;
	ip4->ttl = 8;
	ip4->saddr = saddr4.sin_addr.s_addr;
	ip4->daddr = daddr4.sin_addr.s_addr;
	ip4->check = get_ip_csum(_ip, sizeof(*ip4) >> 1, 0);

	return sizeof(*ip4);
}

static int fill_ip6(void *_ip)
{
	struct ipv6hdr *ip6 = _ip;

	ip6->version = 6;
	ip6->payload_len = htons(sizeof(struct udphdr) + cfg_payload_len);
	ip6->nexthdr = IPPROTO_UDP;
	ip6->hop_limit = 8;
	ip6->saddr = saddr6.sin6_addr;
	ip6->daddr = daddr6.sin6_addr;

	return sizeof(*ip6);
}

static void fill_udp(void *_udp)
{
	struct udphdr *udp = _udp;

	udp->source	= htons(8000);
	udp->dest	= htons(8000);
	udp->len	= htons(sizeof(*udp) + cfg_payload_len);
	udp->check	= 0;

	/* check will be filled after packet is completely built */
}

static int fill_trailer_cpacket(void *_trailer, struct timespec *ts)
{
	struct trailer_cpacket *trailer = _trailer;

	trailer->secs = htonl(ts->tv_sec);
	trailer->nsecs = htonl(ts->tv_nsec);

	return sizeof(*trailer);
}

static int fill_trailer_ttag(void *_trailer, struct timespec *ts)
{
	struct trailer_ttag *trailer = _trailer;
	uint64_t ts64;

	ts64 = (ts->tv_sec * 1000ULL * 1000 * 1000) + ts->tv_nsec;

	trailer->ts[0] = (ts64 & 0xFF0000000000) >> 40;
	trailer->ts[1] = (ts64 & 0xFF00000000) >> 32;
	trailer->ts[2] = (ts64 & 0xFF000000) >> 24;
	trailer->ts[3] = (ts64 & 0xFF0000) >> 16;
	trailer->ts[4] = (ts64 & 0xFF00) >> 8;
	trailer->ts[5] =  ts64 & 0xFF;

	return sizeof(*trailer);
}

static int fill_trailer_brcm(void *_trailer, struct timespec *ts)
{
	struct trailer_brcm *trailer = _trailer;

	trailer->ts[0] = ((ts->tv_sec >> 2) & 0xFF00) >> 8;
	trailer->ts[1] =  (ts->tv_sec >> 2) & 0x00FF;
	trailer->ts[2] =  (ts->tv_sec & 0x3) << 6;

	trailer->ts[2] |= (ts->tv_nsec & 0x3F000000) >> 24;
	trailer->ts[3] =  (ts->tv_nsec & 0x00FF0000) >> 16;
	trailer->ts[4] =  (ts->tv_nsec & 0x0000FF00) >> 8;
	trailer->ts[5] =   ts->tv_nsec & 0x000000FF;

	return sizeof(*trailer);
}

static int fill_trailer_none(void *_trailer, struct timespec *ts)
{
	return 0;
}

static int fill_trailer(void *_trailer)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	printf("ts: %lu.%lu\n", ts.tv_sec, ts.tv_nsec);

	return cfg_trailer_fn(_trailer, &ts);
}

static void parse_args(int argc, char *const argv[])
{
	const char *daddr = NULL, *saddr = NULL;
	bool has_dmac = false;
	int c;

	while ((c = getopt(argc, argv, "46d:D:i:n:S:t:")) != -1) {
		switch (c) {
		case '4':
			cfg_family = PF_INET;
			cfg_family_eth = htons(ETH_P_IP);
			break;
		case '6':
			cfg_family = PF_INET6;
			cfg_family_eth = htons(ETH_P_IPV6);
			break;
		case 'd':
			memcpy(cfg_mac_dst, optarg, ETH_ALEN);
			has_dmac = true;
			break;
		case 'D':
			daddr = optarg;
			break;
		case 'i':
			cfg_ifindex = if_nametoindex(optarg);
			break;
		case 'n':
			cfg_num_pkt = strtoul(optarg, NULL, 0);
			if (cfg_num_pkt > 100)
				error(1, 0, "-n exceeds max (100)");
			break;
		case 'S':
			saddr = optarg;
			break;
		case 't':
			if (!strcmp(optarg, "cpacket"))
				cfg_trailer_fn = fill_trailer_cpacket;
			else if (!strcmp(optarg, "ttag"))
				cfg_trailer_fn = fill_trailer_ttag;
			else if (!strcmp(optarg, "brcm"))
				cfg_trailer_fn = fill_trailer_brcm;
			else if (!strcmp(optarg, "none"))
				cfg_trailer_fn = fill_trailer_none;
			else
				error(1, 0, "unknown trailer type: %s", optarg);
			break;
		default:
			error(1, 0, "unknown arg %c", c);
		}
	}

	if (!has_dmac || !daddr || !saddr)
		error(1, 0, "Must pass -d <mac_daddr> -D <daddr> and -S <saddr>");

	if (!cfg_ifindex)
		error(1, 0, "No valid device (-i)");

	if (cfg_family == PF_INET6) {
		if (inet_pton(cfg_family, daddr, &daddr6.sin6_addr) != 1)
			error(1, errno, "Cannot parse ipv6 -D");
		if (inet_pton(cfg_family, saddr, &saddr6.sin6_addr) != 1)
			error(1, errno, "Cannot parse ipv6 -S");
	} else {
		if (inet_pton(cfg_family, daddr, &daddr4.sin_addr) != 1)
			error(1, errno, "Cannot parse ipv4 -D");
		if (inet_pton(cfg_family, saddr, &saddr4.sin_addr) != 1)
			error(1, errno, "Cannot parse ipv4 -S");
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_ll paddr = { 0 };
	union trailer_storage trailer;
	struct msghdr msg = { 0 };
	union ip_storage ip;
	struct udphdr udp;
	char payload[cfg_payload_len];
	struct iovec iov[4];
	int ip_len, trailer_len;
	int fd, ret, val;

	parse_args(argc, argv);

	fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	val = 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &val, sizeof(val)))
		error(1, errno, "setsockopt mark");

	paddr.sll_protocol = cfg_family_eth;
	paddr.sll_ifindex = cfg_ifindex;
	memcpy(paddr.sll_addr, cfg_mac_dst, sizeof(cfg_mac_dst));

	fill_udp(&udp);
	memset(payload, 'a', sizeof(payload));
	if (cfg_family == PF_INET) {
		ip_len = fill_ip4(&ip.ip4);
		fill_udp_csum(&udp, &ip.ip4.saddr, sizeof(ip.ip4.saddr),
			      payload, sizeof(payload));
	} else {
		ip_len = fill_ip6(&ip.ip6);
		fill_udp_csum(&udp, &ip.ip6.saddr, sizeof(ip.ip6.saddr),
			      payload, sizeof(payload));
	}

	trailer_len = fill_trailer(&trailer);

	iov[0].iov_base = &ip;
	iov[0].iov_len = ip_len;

	iov[1].iov_base = &udp;
	iov[1].iov_len = sizeof(udp);

	iov[2].iov_base = payload;
	iov[2].iov_len = cfg_payload_len;

	iov[3].iov_base = &trailer;
	iov[3].iov_len = trailer_len;

	msg.msg_iov = iov;
	msg.msg_iovlen = trailer_len ? 4 : 3;

	msg.msg_name = (void *)&paddr;
	msg.msg_namelen = sizeof(paddr);

	while (cfg_num_pkt--) {
		ret = sendmsg(fd, &msg, 0);
		if (ret == -1)
			error(1, errno, "write");

		fill_trailer(&trailer);
	}

	if (close(fd))
		error(1, errno, "close");

	return 0;
}
