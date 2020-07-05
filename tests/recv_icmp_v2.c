/* Trigger and read an ICMP(v6) destination unreachable response
 *
 * Test by changing icmp(v6)_send to include this extra data. Note that
 * icmp_send expects network byte order, while icmpv6_send expects host
 * byte order.
 *
 * @@ -2348,7 +2348,7 @@ int __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
 * -       icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
 * +       icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, htonl(32 << 16)); // be32
 * 
 * @@ -925,7 +925,7 @@ int __udp6_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
 * -       icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
 * +       icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 32 << 16); // u32
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <limits.h>
#include <linux/errqueue.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct cfg {
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	socklen_t addrlen;

	struct cmsghdr cm;
	struct sock_extended_err serr;
};

static struct cfg cfg_ipv4 = {
	.addr4.sin_family = PF_INET,
	.addr4.sin_port = 0x0020,
	.addr4.sin_addr.s_addr = 1 << 24 | 127,
	.addrlen = sizeof(cfg_ipv4.addr4),

	.cm.cmsg_level = SOL_IP,
	.cm.cmsg_type = IP_RECVERR,

	.serr.ee_origin = SO_EE_ORIGIN_ICMP,
	.serr.ee_type = ICMP_DEST_UNREACH,
	.serr.ee_code = ICMP_PORT_UNREACH,
};

static struct cfg cfg_ipv6 = {
	.addr6.sin6_family = PF_INET6,
	.addr6.sin6_port = 0x0020,
	.addr6.sin6_addr.s6_addr[15] = 1,
	.addrlen = sizeof(cfg_ipv6.addr6),

	.cm.cmsg_level = SOL_IPV6,
	.cm.cmsg_type = IPV6_RECVERR,

	.serr.ee_origin = SO_EE_ORIGIN_ICMP6,
	.serr.ee_type = ICMPV6_DEST_UNREACH,
	.serr.ee_code = ICMPV6_PORT_UNREACH,
};

static void send_until_errconn(int fd)
{
	static char data[1000];
	int ret;

retry:
	ret = send(fd, data, sizeof(data), MSG_DONTWAIT);
	if (ret == sizeof(data)) {
		sleep(1);
		goto retry;
	}
	if (ret != -1)
		error(1, 0, "sendto: expected err");
	if (errno != ECONNREFUSED)
		error(1, errno, "sendto");
}

static void poll_err(int fd)
{
	struct pollfd pfd = { 0 };
	int ret;

	pfd.fd = fd;
	pfd.events = 0;
	ret = poll(&pfd, 1, 100);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		error(1, 0, "poll: timeout");
	if (pfd.revents != POLLERR)
		error(1, 0, "poll 0x%x", pfd.revents);
}

static void parse_errqueue(struct msghdr *msg, struct cfg *cfg, int len)
{
	struct sock_extended_err *serr;
	struct cmsghdr *cm;

	for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
		if (cm->cmsg_level != cfg->cm.cmsg_level ||
		    cm->cmsg_type != cfg->cm.cmsg_type)
			error(1, 0, "cm_level=%u cm_type=%u\n",
			      cm->cmsg_level, cm->cmsg_type);

		serr = (void *)CMSG_DATA(cm);
		if (serr->ee_origin != cfg->serr.ee_origin ||
		    serr->ee_type != cfg->serr.ee_type ||
		    serr->ee_code != cfg->serr.ee_code)
			error(1, 0, "ee origin=%u type=%u code=%u",
			      serr->ee_origin, serr->ee_type, serr->ee_code);

		fprintf(stderr, "len=%u extension_off=%u ee_info=%x\n",
			len, serr->ee_data, serr->ee_info);

		fprintf(stderr, "rfc4884 len=%d flags=0x%x res=%d\n",
				serr->ee_rfc4884.len,
				serr->ee_rfc4884.flags,
				serr->ee_rfc4884.reserved);
	}
}

static void recv_errqueue(int fd, struct cfg *cfg)
{
	static char payload[1000];
	static char control[1000];
	struct msghdr msg = { 0 };
	struct iovec iov = { 0 };
	int ret;

	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	msg.msg_iov = &iov;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
	if (ret == -1)
		error(1, errno, "recv err");

	if (msg.msg_flags & MSG_CTRUNC)
		error(1, errno, "recv err: control truncated");

	parse_errqueue(&msg, cfg, ret);
}

static void do_test(struct cfg *cfg, bool explicit_rfc4884)
{
	int fd, val;

	fd = socket(cfg->addr.sa_family, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	val = 1;
	if (setsockopt(fd, cfg->cm.cmsg_level, cfg->cm.cmsg_type,
		       &val, sizeof(val)))
		error(1, errno, "setsockopt recverr");

	/* negative test: do not accept out of bounds value */
	val = 2;
	if (explicit_rfc4884 &&
	    !setsockopt(fd, SOL_IP, IP_RECVERR_RFC4884,
		      &val, sizeof(val)))
		error(1, errno, "setsockopt recverr_rfc4884 val=-1");

	val = 1;
	if (explicit_rfc4884 &&
	    setsockopt(fd, SOL_IP, IP_RECVERR_RFC4884,
		      &val, sizeof(val)))
		error(1, errno, "setsockopt recverr_rfc4884");

	if (connect(fd, &cfg->addr, cfg->addrlen))
		error(1, errno, "connect");

	send_until_errconn(fd);

	poll_err(fd);

	recv_errqueue(fd, cfg);
	sleep(1);
}

int main(int argc, char **argv)
{
	do_test(&cfg_ipv6, false);
	do_test(&cfg_ipv4, false);
	do_test(&cfg_ipv4, true);

	fprintf(stderr, "OK\n");
	return 0;
}

