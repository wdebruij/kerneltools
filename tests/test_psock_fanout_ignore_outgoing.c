// SPDX-License-Identifier: GPL-2.0

/* Test PACKET_FANOUT_FLAG_IGNORE_OUTGOING
 *
 * Run a packet socket
 * and observe bidirectional traffic:
 *   ./test -p 12867 -i eth0
 *
 * Run with socket option PACKET_IGNORE_OUTGOING
 * and observe unidirectional traffic:
 *   ./test -p 12867 -i eth0 -o
 *
 * Run two sockets in a fanout group
 * and observe bidirectional traffic *with or without -o*
 *   ./test -p 12867 -i eth0 -F -o
 *
 * Run two sockets in a fanout group with flag PACKET_FANOUT_FLAG_IGNORE_OUTGOING
 * and observe unidirection traffic again:
 *   ./test -p 12867 -i eth0 -F -O
 *
 * Using port 12867 here because running tcp_rr from github.com/google/neper
 * as background traffic generator.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PACKET_FANOUT_FLAG_IGNORE_OUTGOING
#define PACKET_FANOUT_FLAG_IGNORE_OUTGOING 0x4000
#endif

static char *cfg_ifname = "eth0";
static bool cfg_fanout;
static uint16_t cfg_fanout_flags;
static uint16_t cfg_port;			/* network endian */
static bool cfg_sock_ignore_outgoing;

static int psock_socket(void)
{
	struct sockaddr_ll addr = { 0 };
	int fd, one = 1;

	fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (fd == -1)
		error(1, errno, "socket");

	if (cfg_sock_ignore_outgoing &&
	    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)))
		error(1, errno, "setsockopt ignore outgoing");

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = if_nametoindex(cfg_ifname);
	if (addr.sll_ifindex == 0)
		error(1, 0, "if_nametoindex: unknown device: %s\n", cfg_ifname);
	if (bind(fd, (void *)&addr, sizeof(addr)))
		error(1, errno, "bind");

	return fd;
}

static void psock_join_fanout(int fd, uint16_t opt_flags)
{
	struct fanout_args args = {
		.id = 2,
		.type_flags = PACKET_FANOUT_RND | opt_flags,
		.max_num_members = 256.
	};

	if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &args, sizeof(args)))
		error(1, errno, "setsockopt fanout");
}

static int psock_recv_nonblock(int fd)
{
	struct {
		struct ethhdr eth;
		struct ipv6hdr iph;
		union {
			struct udphdr uh;
			struct tcphdr th;
		};
	} __attribute__((packed)) headers;
	char daddr_str[INET6_ADDRSTRLEN];
	char saddr_str[INET6_ADDRSTRLEN];
	int ret;

	ret = recv(fd, &headers, sizeof(headers), MSG_DONTWAIT);
	if (ret == -1 && errno == EAGAIN)
		return 0;
	if (ret == -1)
		error(1, errno, "recv");

	/* ignore packets that may be too short */
	if (ret < sizeof sizeof(headers))
		return 0;

	if (!inet_ntop(AF_INET6, &headers.iph.daddr, daddr_str, sizeof(daddr_str)))
		error(1, errno, "inet_ntop");
	if (!inet_ntop(AF_INET6, &headers.iph.saddr, saddr_str, sizeof(saddr_str)))
		error(1, errno, "inet_ntop");

	if (headers.iph.nexthdr == IPPROTO_TCP) {
		if (cfg_port && headers.th.source != cfg_port && headers.th.dest != cfg_port)
			return 0;
		printf("TCP: %s:%u -> %s:%u\n",
		       saddr_str, ntohs(headers.th.source),
		       daddr_str, ntohs(headers.th.dest));
	} else if (headers.iph.nexthdr == IPPROTO_UDP) {
		if (cfg_port && headers.uh.source != cfg_port && headers.uh.dest != cfg_port)
			return 0;
		printf("UDP: %s:%u -> %s:%u\n",
		       saddr_str, ntohs(headers.th.source),
		       daddr_str, ntohs(headers.th.dest));
	} else {
		printf("PROTO[%u]: %s -> %s\n",
		       headers.iph.nexthdr, saddr_str, daddr_str);
	}

	return ret;
}

static unsigned long gettimeofday_msec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "Fi:p:oO")) != -1) {
		switch (c) {
		case 'F':
			cfg_fanout = true;
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'p':
			cfg_port = htons(strtoul(optarg, NULL, 0));
			break;
		case 'o':
			cfg_sock_ignore_outgoing = true;
			break;
		case 'O':
			cfg_fanout_flags |= PACKET_FANOUT_FLAG_IGNORE_OUTGOING;
			break;
		default:
			error(1, 0, "unknown arg: %c\n", c);
		}
	}
}

int main(int argc, char **argv)
{
	unsigned long tstop;
	int fd1, fd2, budget;

	parse_opts(argc, argv);

	fd1 = psock_socket();
	if (cfg_fanout) {
		fd2 = psock_socket();
		psock_join_fanout(fd1, cfg_fanout_flags);
		psock_join_fanout(fd2, cfg_fanout_flags);
	}

	tstop = gettimeofday_msec() + 1000;
	do {
		for (budget = 16; psock_recv_nonblock(fd1) && budget; budget--) {}
		if (cfg_fanout)
			for (budget = 16; psock_recv_nonblock(fd2) && budget; budget--) {}

		/* rate limit output. this is not a serious sniffer. */
		usleep(10 * 1000UL);
	} while (gettimeofday_msec() < tstop);

	if (cfg_fanout &&
	    close(fd2))
		error(1, errno, "close");
	if (close(fd1))
		error(1, errno, "close");

	return 0;
}

