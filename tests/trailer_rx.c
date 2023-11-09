// SPDX-License-Identifier: GPL-2.0

/* Receive a UDP packet with Onload's trailer timestamp feature */

#define _GNU_SOURCE

#include <stddef.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <net/if.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
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

static unsigned int cfg_num_pkt = 1;

/* Timestamping API */
struct onload_timestamp {
       uint64_t sec;
       uint32_t nsec;
       uint32_t nsec_frac : 24;
       uint32_t reserved  : 8;
};

enum onload_timestamping_flags {
       ONLOAD_TIMESTAMPING_FLAG_TX_NIC = 1 << 0,
       ONLOAD_TIMESTAMPING_FLAG_RX_NIC = 1 << 1,
       ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET = 1 << 2,
};

__attribute__((weak)) int onload_timestamping_request(int fd, unsigned flags);

static void do_recv_tstamp(int fd)
{
	char ctrl[CMSG_SPACE(sizeof(struct onload_timestamp)) * 2];
	struct onload_timestamp *ots;
	char rxbuf[1452];
	struct msghdr msg = {0};
	struct iovec iov = {0};
	struct cmsghdr *cm;
	int count = 0;
	int ret = 0;

	iov.iov_base = rxbuf;
	iov.iov_len = sizeof(rxbuf);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof(ctrl);

	ret = recvmsg(fd, &msg, 0);
	if (ret == -1)
		error(1, errno, "recvmsg");
	printf("recv: %dB\n", ret);

	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET &&
		    cm->cmsg_type == SCM_TIMESTAMPING) {
			ots = (void *) CMSG_DATA(cm);
			printf("ts nic: %lu.%u (.%u) trailer: %lu.%u (.%u)\n",
			       ots[0].sec, ots[0].nsec, ots[0].nsec_frac,
			       ots[1].sec, ots[1].nsec, ots[1].nsec_frac);
		}
	}
	count++;
}

static void parse_args(int argc, char *const argv[])
{
	int c;

	while ((c = getopt(argc, argv, "n:")) != -1) {
		switch (c) {
		case 'n':
			cfg_num_pkt = strtoul(optarg, NULL, 0);
			if (cfg_num_pkt > 100)
				error(1, 0, "-n exceeds max (100)");
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_in6 addr = { 0 };
	int fd;

	parse_args(argc, argv);

	fd = socket(PF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	addr.sin6_family = PF_INET6;
	addr.sin6_port = htons(8000);
	addr.sin6_addr = in6addr_any;
	if (bind(fd, (void *)&addr, sizeof(addr)))
		error(1, errno, "bind");

	if (onload_timestamping_request(fd, ONLOAD_TIMESTAMPING_FLAG_RX_NIC |
					    ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET))
		error(1, errno, "onload_timestamping_request");

	while (cfg_num_pkt--)
		do_recv_tstamp(fd);

	if (close(fd))
		error(1, errno, "close");

	return 0;
}
