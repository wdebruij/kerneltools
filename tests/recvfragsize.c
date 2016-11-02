/* Test IP(V6)_RECVFRAGSIZE socket option */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IP_RECVFRAGSIZE 25
#define IPV6_RECVFRAGSIZE 77

static int cfg_dest_port = 6000;
static int cfg_expected_fragsize = 1300;
static int cfg_proto_l3 = PF_INET6;
static int cfg_proto_l4 = SOCK_DGRAM;

static int socket_rx(int domain, int type, int protocol,
		     struct sockaddr *addr, socklen_t alen)
{
	int fd, level, optname, one = 1;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		error(1, errno, "socket");

	if (domain == PF_INET6) {
		level = SOL_IPV6;
		optname = IPV6_RECVFRAGSIZE;
	} else {
		level = SOL_IP;
		optname = IP_RECVFRAGSIZE;
	}

	if (setsockopt(fd, level, optname, &one, sizeof(one)))
		error(1, errno, "setsockopt recvfragsize (%u.%u)",
				level, optname);

	if (bind(fd, addr, alen))
		error(1, errno, "bind");

	return fd;
}

static int socket_rx_ipv6(int type, int protocol)
{
	struct sockaddr_in6 addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(cfg_dest_port),
		.sin6_addr	= in6addr_any,
	};

	return socket_rx(PF_INET6, type, protocol, (void*) &addr, sizeof(addr));
}

static int socket_rx_ipv4(int type, int protocol)
{
	struct sockaddr_in addr = {
		.sin_family		= AF_INET,
		.sin_port		= htons(cfg_dest_port),
		.sin_addr.s_addr	= htons(INADDR_ANY),
	};

	return socket_rx(PF_INET, type, protocol, (void*) &addr, sizeof(addr));
}

static void poll_one(int fd)
{
	struct pollfd pfd = {0};
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;

	ret = poll(&pfd, 1, 1000);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		error(1, 0, "poll: timeout");
	if (!(pfd.revents & POLLIN))
		error(1, 0, "poll: unexpected event(s) 0x%x\n", pfd.revents);
}

static void rx_one(int fd, int level, int optname)
{
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char control[2 * CMSG_SPACE(int)];
	int ret, size, num_cmsg = 0;

	poll_one(fd);

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, MSG_TRUNC);
	if (ret == -1)
		error(1, errno, "recvmsg");
	if (msg.msg_flags & MSG_CTRUNC)
		error(1, 0, "recvmsg: truncated cmsg");
	fprintf(stderr, "recv: %uB\n", ret);

	for (cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg && cmsg->cmsg_len;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != level || cmsg->cmsg_type != optname)
			error(1, 0, "wrong cmsg 0x%x.0x%x",
			      cmsg->cmsg_level, cmsg->cmsg_type);
		num_cmsg++;
		fprintf(stderr, "cmsg_level=%u cmsg_type=%u\n",
				cmsg->cmsg_level, cmsg->cmsg_type);
		size = *((int*) CMSG_DATA(cmsg));
		fprintf(stderr, "max fragsize: %u\n", size);
	}

	if (num_cmsg > 1)
		error(1, 0, "unexpected #cmsg: %u\n", num_cmsg);
	if (num_cmsg == 1 && size != cfg_expected_fragsize)
		error(1, 0, "unexpected frag size: %u\n", size);
}

static void run_one_ipv6(int type)
{
	int fd;

	fprintf(stderr, "ipv6 %s\n", type == SOCK_DGRAM ? "udp" : "raw");

	/* IPv6 fragments are 8-byte aligned, expect for the last */
	cfg_expected_fragsize = cfg_expected_fragsize >> 3 << 3;

	fd = socket_rx_ipv6(type, type == SOCK_RAW ? IPPROTO_EGP : 0);
	rx_one(fd, SOL_IPV6, IPV6_RECVFRAGSIZE);
	if (close(fd))
		error(1, errno, "close");
}

static void run_one_ipv4(int type)
{
	int fd;

	fprintf(stderr, "ipv4 %s\n", type == SOCK_DGRAM ? "udp" : "raw");

	fd = socket_rx_ipv4(type, type == SOCK_RAW ? IPPROTO_EGP : 0);
	rx_one(fd, SOL_IP, IP_RECVFRAGSIZE);
	if (close(fd))
		error(1, errno, "close");
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "46p:ru")) != -1) {
		switch (c) {
		case '4':
			cfg_proto_l3 = PF_INET;
			break;
		case '6':
			cfg_proto_l3 = PF_INET6;
			break;
		case 'p':
			cfg_dest_port = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			cfg_proto_l4 = SOCK_RAW;
			break;
		case 'u':
			cfg_proto_l4 = SOCK_DGRAM;
			break;
		default:
			error(1, 0, "invalid option %c\n", c);
		}
	}
}

int main(int argc, char **argv)
{
	parse_opts(argc, argv);

	if (cfg_proto_l3 == PF_INET)
		run_one_ipv4(cfg_proto_l4);
	else
		run_one_ipv6(cfg_proto_l4);

	fprintf(stderr, "OK. All tests passed\n");
	return 0;
}

