/*
 * Test recv cmsg IP_CHECKSUM
 *
 * For both IPv4 and v4-mapped-v6:
 * - read 100 B packet
 * - peek 100 B packet at 2 B offset
 *
 * The cmsg is expected to arrive with CHECKSUM_COMPLETE, including
 * on receive checksum conversion. It does not work with IPv6 or with
 * hardware checksum disabled.
 *
 * To run: start on one host and send traffic from another host:
 *
 *   dd if=/dev/zero bs=1 count=100 | sed 's/./\x01/2' > payload
 *   for i in 1 2; do nc -p 9000 -q 1 -u $hostA 8000 < payload; done
 *
 * The sum of the payload of range [2, 99] is 0.
 * The sum of the payload of range [0, 99] is 1.
 *
 * Expected sum16 output is
 *   peek: 0xFFFF	(because all zeroes)
 *   read: 0x0100	(because one \x01 halfword)
 *
 *
 * Author: Willem de Bruijn (willemb@google.com)
 * GPL v2 applies
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <error.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define IP_CHECKSUM 23

#define CFG_PORT	8000
#define PAYLOAD_CHAR	0
#define PAYLOAD_LEN	100
#define PEEK_OFF	2

static inline uint16_t csum_fold(__wsum csum)
{
	uint32_t sum = csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t) sum;
}

static void do_rx(int fd, bool peek)
{
	char rbuf[100];
	struct cmsghdr *cm;
	struct msghdr msg = {0};
	struct iovec iov = {0};
	char control[CMSG_SPACE(sizeof(__wsum))];
	int ret, expected;

	iov.iov_base = rbuf;
	iov.iov_len = sizeof(rbuf);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, peek ? MSG_PEEK : 0);
	if (ret == -1)
		error(1, errno, "recv");
	if (msg.msg_flags & MSG_TRUNC)
		error(1, errno, "recv: truncated data");
	if (msg.msg_flags & MSG_CTRUNC)
		error(1, errno, "recv: truncated control");
	
	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		__wsum check32;

		if (cm->cmsg_level != SOL_IP)
			error(1, 0, "cmsg: level=%u", cm->cmsg_level);
		if (cm->cmsg_type != IP_CHECKSUM)
			error(1, 0, "cmsg: type=%u", cm->cmsg_level);

		check32 = *((__wsum*) CMSG_DATA(cm));
		fprintf(stderr, "csum: sum32=0x%0x sum16=%hx ~sum16=%hx\n",
			check32, csum_fold(check32), ~csum_fold(check32));
	}

	expected = PAYLOAD_LEN - (peek ? PEEK_OFF : 0);
	if (ret != expected)
		error(1, 0, "recv: %uB != %uB", ret, expected);
	if (rbuf[0] != PAYLOAD_CHAR)
		error(1, 0, "recv: payload mismatch");
}

static void do_main(struct sockaddr *addr, socklen_t alen)
{
	int fd, ret, one = 1, two = 2;

	fd = socket(addr->sa_family, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket rx");

	ret = bind(fd, addr, alen);
	if (ret)
		error(1, errno, "bind rx");

	if (setsockopt(fd, SOL_IP, IP_CHECKSUM, &one, sizeof(one)))
		error(1, errno, "setsockopt csum");

	if (setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &two, sizeof(two)))
		error(1, errno, "setsockopt peek_off");

	do_rx(fd, true);
	do_rx(fd, false);

	if (close(fd))
		error(1, errno, "close");
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr4 = {0};
	struct sockaddr_in6 addr6 = {0};

	fprintf(stderr, "PF_INET\n");
	addr4.sin_family = PF_INET;
	addr4.sin_port = htons(CFG_PORT);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	do_main((void *) &addr4, sizeof(addr4));

	fprintf(stderr, "PF_INET6\n");
	addr6.sin6_family = PF_INET6;
	addr6.sin6_port = htons(CFG_PORT);
	addr6.sin6_addr = in6addr_any;
	do_main((void *) &addr6, sizeof(addr6));

	return 0;
}
