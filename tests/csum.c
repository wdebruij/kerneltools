/*
 * Copyright (C) 2020 Google LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Test hardware checksumming
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PAYLOAD_LEN 100

static bool cfg_error;
static int cfg_family = PF_INET6;
static int cfg_num_pkt = 4;
static bool cfg_do_rx = true;
static bool cfg_do_tx = true;
static int cfg_proto = IPPROTO_UDP;
static int cfg_payload_char = 'a';
static int cfg_payload_len = MAX_PAYLOAD_LEN;
static uint16_t cfg_port_dst = 34000;
static uint16_t cfg_port_src = 33000;
static bool cfg_udp_send;
static bool cfg_zero_disable; /* skip checksum: set to zero (udp only) */
static bool cfg_zero_sum;		 /* create packet that adds up to zero */

static struct sockaddr_in cfg_daddr4 = {.sin_family = AF_INET};
static struct sockaddr_in cfg_saddr4 = {.sin_family = AF_INET};
static struct sockaddr_in6 cfg_daddr6 = {.sin6_family = AF_INET6};
static struct sockaddr_in6 cfg_saddr6 = {.sin6_family = AF_INET6};

struct pkt_v4 {
	struct iphdr iph;
	struct udphdr uh;
	char data[MAX_PAYLOAD_LEN];
} __attribute__((packed));

struct pkt_v6 {
	struct ipv6hdr ip6h;
	struct udphdr uh;
	char data[MAX_PAYLOAD_LEN];
} __attribute__((packed));

struct pkt {
	union {
		struct pkt_v4 v4;
		struct pkt_v6 v6;
	};
} __attribute__((packed));

static uint32_t checksum_nofold(void *data, size_t len, uint32_t sum) {
	uint16_t *words = data;
	int i;

	for (i = 0; i < len / 2; i++) sum += words[i];

	if (len & 1) sum += ((char *)data)[len - 1];

	return sum;
}

static uint16_t checksum_fold(void *data, size_t len, uint32_t sum) {
	sum = checksum_nofold(data, len, sum);

	while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static uint16_t checksum(void *th, uint16_t proto, size_t len) {
	uint32_t sum;
	int alen;

	alen = cfg_family == PF_INET6 ? 32 : 8;

	sum = checksum_nofold(th - alen, alen, 0);
	sum += htons(proto);
	sum += htons(len);

	return checksum_fold(th, len, sum);
}

static void *build_packet_ipv4(void *_iph) {
	struct iphdr *iph = _iph;

	memset(iph, 0, sizeof(*iph));

	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = 8;
	iph->protocol = cfg_proto;
	iph->saddr = cfg_saddr4.sin_addr.s_addr;
	iph->daddr = cfg_daddr4.sin_addr.s_addr;
	/* kernel fills checksum and total length */

	return iph + 1;
}

static void *build_packet_ipv6(void *_ip6h) {
	struct ipv6hdr *ip6h = _ip6h;

	memset(ip6h, 0, sizeof(*ip6h));

	ip6h->version = 6;
	ip6h->payload_len = htons(sizeof(struct udphdr) + cfg_payload_len);
	ip6h->nexthdr = cfg_proto;
	ip6h->hop_limit = 8;
	ip6h->saddr = cfg_saddr6.sin6_addr;
	ip6h->daddr = cfg_daddr6.sin6_addr;

	return ip6h + 1;
}

static void *build_packet_udp(void *_uh) {
	struct udphdr *uh = _uh;

	memset(uh, 0, sizeof(*uh));

	uh->source = htons(cfg_port_src);
	uh->dest = htons(cfg_port_dst);
	uh->len = htons(sizeof(*uh) + cfg_payload_len);

	/* choose source port so that uh->check adds up to zero */
	if (cfg_zero_sum) {
		uh->source = 0;
		uh->source = checksum(uh, IPPROTO_UDP, sizeof(*uh) + cfg_payload_len);

		fprintf(stderr, "sport: %hu -> %hu\n", cfg_port_src, ntohs(uh->source));
		cfg_port_src = ntohs(uh->source);
	}

	if (cfg_zero_disable)
		uh->check = 0;
	else
		uh->check = checksum(uh, IPPROTO_UDP, sizeof(*uh) + cfg_payload_len);

	if (cfg_error) uh->check = ~uh->check;

	fprintf(stderr, "checksum: 0x%x\n", uh->check);
	return uh + 1;
}

static int build_packet(char *buf, int max_len) {
	char *off;

	memset(buf, cfg_payload_char, max_len);

	if (cfg_family == PF_INET)
		off = build_packet_ipv4(buf);
	else
		off = build_packet_ipv6(buf);

	off = build_packet_udp(off);

	return off - buf + cfg_payload_len;
}

static void send_connect(int fd) {
	if (cfg_family == PF_INET6) {
		/* may have been updated by cfg_zero_disable */
		cfg_saddr6.sin6_port = htons(cfg_port_src);

		if (bind(fd, (void *)&cfg_saddr6, sizeof(cfg_saddr6)))
			error(1, errno, "bind dgram 6");
		if (connect(fd, (void *)&cfg_daddr6, sizeof(cfg_daddr6)))
			error(1, errno, "connect dgram 6");
	} else {
		/* may have been updated by cfg_zero_disable */
		cfg_saddr4.sin_port = htons(cfg_port_src);

		if (bind(fd, (void *)&cfg_saddr4, sizeof(cfg_saddr4)))
			error(1, errno, "bind dgram 4");
		if (connect(fd, (void *)&cfg_daddr4, sizeof(cfg_daddr4)))
			error(1, errno, "connect dgram 4");
	}
}

static void send_raw(const char *buf, int len) {
	int fd, ret;

	fd = socket(cfg_family, SOCK_RAW, IPPROTO_RAW);
	if (fd == -1)
		error(1, errno, "socket raw: no CAP_NET_RAW?");

	send_connect(fd);

	ret = write(fd, buf, len);
	if (ret == -1)
		error(1, errno, "write");
	if (ret != len)
		error(1, 0, "write: %d", ret);

	if (close(fd))
		error(1, errno, "close raw");
}

static void send_udp(void) {
	static char buf[MAX_PAYLOAD_LEN];
	int fd, ret;

	fd = socket(cfg_family, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket dgram");

	send_connect(fd);

	memset(buf, cfg_payload_char, cfg_payload_len);

	ret = write(fd, buf, cfg_payload_len);
	if (ret == -1)
		error(1, errno, "write dgram");
	if (ret != cfg_payload_len)
		error(1, 0, "write dgram: %d", ret);

	if (close(fd))
		error(1, errno, "close dgram");
}

static int recv_prepare_udp(void) {
	int fd;

	fd = socket(cfg_family, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket r");

	if (cfg_family == PF_INET6) {
		if (bind(fd, (void *)&cfg_daddr6, sizeof(cfg_daddr6)))
			error(1, errno, "bind r");
	} else {
		if (bind(fd, (void *)&cfg_daddr4, sizeof(cfg_daddr4)))
			error(1, errno, "bind r");
	}

	return fd;
}

static int recv_prepare_packet(void) {
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM,
		    cfg_family == PF_INET ? htons(ETH_P_IP) : htons(ETH_P_IPV6));
	if (fd == -1)
		error(1, errno, "socket p");

	return fd;
}

static int recv_udp(int fd) {
	static char buf[MAX_PAYLOAD_LEN];
	int ret, count = 0;

	while (1) {
		ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (ret == -1 && errno == EAGAIN)
			break;
		if (ret == -1)
			error(1, errno, "recv r");

		fprintf(stderr, "udp: len=%u\n", ret);
		count++;
	}

	return count;
}

static int recv_verify_packet_v4(struct pkt_v4 *pkt, int len) {
	uint16_t csum;

	if (len < sizeof(pkt->iph) + sizeof(pkt->uh) ||
	    pkt->iph.protocol != IPPROTO_UDP ||
	    pkt->uh.dest != htons(cfg_port_dst))
		return 0;

	csum = checksum(&pkt->uh, pkt->iph.protocol, len - sizeof(pkt->iph));
	fprintf(stderr, "pkt: sport=%hu len=%u verify=0x%hx\n",
		ntohs(pkt->uh.source), len, csum);

	/* csum must be zero unless cfg_error indicates bad csum */
	if ((cfg_error && !csum) || (csum && !cfg_error))
		error(1, 0, "pkt: csum ^ error");

	return 1;
}

static int recv_verify_packet_v6(struct pkt_v6 *pkt, int len) {
	uint16_t csum;

	if (len < sizeof(pkt->ip6h) + sizeof(pkt->uh) ||
	    pkt->ip6h.nexthdr != IPPROTO_UDP ||
	    pkt->uh.dest != htons(cfg_port_dst))
		return 0;

	csum = checksum(&pkt->uh, pkt->ip6h.nexthdr, len - sizeof(pkt->ip6h));
	fprintf(stderr, "pkt: sport=%hu len=%u verify=0x%hx\n",
		ntohs(pkt->uh.source), len, csum);

	/* csum must be zero unless cfg_error indicates bad csum */
	if ((cfg_error && !csum) || (csum && !cfg_error))
		error(1, 0, "pkt: csum ^ error");

	return 1;
}

static int recv_packet(int fd) {
	static struct pkt buf;
	int ret, count = 0;

	while (1) {
		ret = recv(fd, &buf, sizeof(buf), MSG_DONTWAIT);
		if (ret == -1 && errno == EAGAIN)
			break;
		if (ret == -1)
			error(1, errno, "recv p");

		if (cfg_family == PF_INET6)
			count += recv_verify_packet_v6(&buf.v6, ret);
		else
			count += recv_verify_packet_v4(&buf.v4, ret);
	}

	return count;
}

static void parse_args(int argc, char *const argv[]) {
	const char *daddr = NULL, *saddr = NULL;
	int c;

	while ((c = getopt(argc, argv, "46D:El:n:RS:TuUzZ")) != -1) {
		switch (c) {
			case '4':
				cfg_family = PF_INET;
				break;
			case '6':
				cfg_family = PF_INET6;
				break;
			case 'D':
				daddr = optarg;
				break;
			case 'E':
				cfg_error = true;
				break;
			case 'l':
				cfg_payload_len = strtol(optarg, NULL, 0);
				break;
			case 'n':
				cfg_num_pkt = strtol(optarg, NULL, 0);
				break;
			case 'R':
				/* only Rx: used with two machine tests */
				cfg_do_tx = false;
				break;
			case 'S':
				saddr = optarg;
				break;
			case 'T':
				/* only Tx: used with two machine tests */
				cfg_do_rx = false;
				break;
			case 'u':
				cfg_proto = IPPROTO_UDP;
				break;
			case 'U':
				/* send using real udp socket,
				 * to exercise tx checksum offload */
				cfg_udp_send = true;
				break;
			case 'z':
				cfg_zero_disable = true;
				break;
			case 'Z':
				cfg_zero_sum = true;
				break;
			default:
				error(1, 0, "unknown arg %c", c);
		}
	}

	if (!daddr || !saddr)
		error(1, 0, "Must pass -D <daddr> and -S <saddr>");

	if (cfg_payload_len > MAX_PAYLOAD_LEN)
		error(1, 0, "Payload length exceeds max");

	if (cfg_zero_disable && cfg_proto != IPPROTO_UDP)
		error(1, 0, "Only UDP supports zero csum");

	if (cfg_family == PF_INET6) {
		cfg_saddr6.sin6_port = htons(cfg_port_src);
		cfg_daddr6.sin6_port = htons(cfg_port_dst);

		if (inet_pton(cfg_family, daddr, &cfg_daddr6.sin6_addr) != 1)
			error(1, errno, "Cannot parse ipv6 -D");
		if (inet_pton(cfg_family, saddr, &cfg_saddr6.sin6_addr) != 1)
			error(1, errno, "Cannot parse ipv6 -S");
	} else {
		cfg_saddr4.sin_port = htons(cfg_port_src);
		cfg_daddr4.sin_port = htons(cfg_port_dst);

		if (inet_pton(cfg_family, daddr, &cfg_daddr4.sin_addr) != 1)
			error(1, errno, "Cannot parse ipv4 -D");
		if (inet_pton(cfg_family, saddr, &cfg_saddr4.sin_addr) != 1)
			error(1, errno, "Cannot parse ipv4 -S");
	}
}

int main(int argc, char *const argv[]) {
	static char buf[sizeof(struct ipv6hdr) +
			sizeof(struct tcphdr) +
			MAX_PAYLOAD_LEN];
	int fdr, fdp, len, i;

	parse_args(argc, argv);

	if (cfg_do_rx) {
		fdp = recv_prepare_packet();
		fdr = recv_prepare_udp();
	}

	if (cfg_do_tx) {
		len = build_packet(buf, sizeof(buf));

		for (i = 0; i < cfg_num_pkt; i++) {
			if (cfg_udp_send)
				send_udp();
			else
				send_raw(buf, len);
		}
	}

	if (cfg_do_rx) {
		int count_udp = 0, count_pkt = 0;

		usleep(1000 * 1000);

		count_udp = recv_udp(fdr);
		count_pkt = recv_packet(fdp);

		if (count_pkt < cfg_num_pkt)
			error(1, 0, "rx: missing packets at pf_packet");

		if (!count_udp && !cfg_error)
			error(1, 0, "rx: missing packets at udp");
		else if (count_udp && cfg_error)
			error(1, 0, "rx: unexpected packets at udp");

		if (close(fdr))
			error(1, errno, "close r");
		if (close(fdp))
			error(1, errno, "close p");
	}

	fprintf(stderr, "OK\n");
	return 0;
}
