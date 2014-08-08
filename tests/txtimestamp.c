/*
 * Copyright 2014 Google Inc.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Conformance tests for software tx timestamping, including
 *
 * - SCHED, SND and ACK timestamps
 * - RAW, UDP and TCP
 * - IPv4 and IPv6
 * - various packet sizes (to test GSO and TSO)
 *
 * Consult the command line arguments for help on running
 * the various testcases.
 *
 * This test requires a dummy TCP server.
 * A simple `nc6 [-u] -l -p $DESTPORT` will do
 *
 * Tested against net-next (09ddb8e)
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. * See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <arpa/inet.h>
#include <asm/types.h>
#include <error.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* should be defined in include/uapi/linux/socket.h */
#define MSG_TSTAMP	0x100000
#define MSG_TSTAMP_ACK	0x200000
#define MSG_TSTAMP_ENQ	0x400000
#define MSG_TSTAMP_ANY	(MSG_TSTAMP | MSG_TSTAMP_ACK | MSG_TSTAMP_ENQ)

#ifndef SCM_TSTAMP_SND
struct scm_timestamping {
	struct timespec ts[3];
};

#define SCM_TSTAMP_SND		0
#define SCM_TSTAMP_SCHED	1
#define SCM_TSTAMP_ACK		2

#define SOF_TIMESTAMPING_OPT_ID		(1<<7)
#define SOF_TIMESTAMPING_TX_SCHED	(1<<8)
#define SOF_TIMESTAMPING_TX_ACK		(1<<9)
#endif

#define NUM_RUNS	4

/* command line parameters */
static int cfg_proto = SOCK_STREAM;
static int cfg_ipproto = IPPROTO_TCP;
static int do_ipv4 = 1;
static int do_ipv6 = 1;
static int payload_len = 10;
static int tstamp_no_payload;
static uint16_t dest_port = 9000;

struct sockaddr_in daddr;
struct sockaddr_in6 daddr6;

/* random globals */
static struct timeval tv;
static struct timespec ts_prev;
static int tstamp_payload_len;

static void __print_timestamp(const char *name, struct timespec *cur,
			      uint32_t key)
{
	if (!(cur->tv_sec | cur->tv_nsec))
		return;

	fprintf(stderr, "  %s: %lu s %lu us (seq=%u, len=%u)",
			name, cur->tv_sec, cur->tv_nsec / 1000,
			key, tstamp_payload_len);

	if ((ts_prev.tv_sec | ts_prev.tv_nsec)) {
		int64_t cur_ms, prev_ms;

		cur_ms = (long) cur->tv_sec * 1000 * 1000;
		cur_ms += cur->tv_nsec / 1000;

		prev_ms = (long) ts_prev.tv_sec * 1000 * 1000;
		prev_ms += ts_prev.tv_nsec / 1000;

		fprintf(stderr, "  (%+ld us)", cur_ms - prev_ms);
	}

	ts_prev = *cur;
	fprintf(stderr, "\n");
}

static void print_timestamp_usr(void)
{
	struct timespec ts;

	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	__print_timestamp("  USR", &ts, 0);

}

static void print_timestamp(struct scm_timestamping *tss, int tstype, int tskey)
{
	const char *tsname;

	switch (tstype) {
	case SCM_TSTAMP_SCHED:
		tsname = "  ENQ";
		break;
	case SCM_TSTAMP_SND:
		tsname = "  SND";
		break;
	case SCM_TSTAMP_ACK:
		tsname = "  ACK";
		break;
	default:
		error(1, 0, "unknown timestamp type: %u",
		tstype);
	}
	__print_timestamp(tsname, &tss->ts[0], tskey);
}

static void __poll(int fd)
{
	struct pollfd pollfd;
	int ret;

	memset(&pollfd, 0, sizeof(pollfd));
	pollfd.events = POLLIN;
	pollfd.fd = fd;
	ret = poll(&pollfd, 1, 100);
	if (ret == -1 && errno != EAGAIN)
		error(1, errno, "poll");
}

static void __recv_errmsg_cmsg(struct msghdr *msg)
{
	struct sock_extended_err *serr = NULL;
	struct scm_timestamping *tss = NULL;
	struct cmsghdr *cm;

	for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET &&
		    cm->cmsg_type == SCM_TIMESTAMPING) {
			tss = (void *) CMSG_DATA(cm);
		} else if ((cm->cmsg_level == SOL_IP &&
		     cm->cmsg_type == IP_RECVERR) ||
		    (cm->cmsg_level == SOL_IPV6 &&
		     cm->cmsg_type == IPV6_RECVERR)) {

			serr = (void *) CMSG_DATA(cm);
			if (serr->ee_errno != ENOMSG ||
			    serr->ee_origin != SO_EE_ORIGIN_TIMESTAMPING) {
				fprintf(stderr, "unknown ip error %d %d\n",
						serr->ee_errno,
						serr->ee_origin);
				serr = NULL;
			}
		} else
			fprintf(stderr, "%d, %d\n",
					cm->cmsg_level, cm->cmsg_type);
	}

	if (serr && tss)
		print_timestamp(tss, serr->ee_info, serr->ee_data);
}

static int recv_errmsg(int fd)
{
	static char ctrl[1024 /* overcommit */];
	static struct msghdr msg;
	struct iovec entry;
	static char *data;
	int ret = 0;

	data = malloc(payload_len);
	if (!data)
		error(1, 0, "malloc");

	memset(&msg, 0, sizeof(msg));
	memset(&entry, 0, sizeof(entry));
	memset(ctrl, 0, sizeof(ctrl));
	memset(data, 0, sizeof(data));

	entry.iov_base = data;
	/* for TCP we specify payload length to read one packet at a time. */
	entry.iov_len = payload_len;
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof(ctrl);

	ret = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (ret == -1 && (errno == EINTR || errno == EWOULDBLOCK))
		goto done;
	if (ret == -1)
		error(1, errno, "recvmsg");

	tstamp_payload_len = ret;
	if (tstamp_no_payload && tstamp_payload_len)
		error(1, 0, "recv: payload when configured without");
	else if (!tstamp_no_payload && !tstamp_payload_len)
		error(1, 0, "recv: no payload when configured with");

	__recv_errmsg_cmsg(&msg);

done:
	free(data);
	return ret == -1;
}

static int setsockopt_ts(int fd, int flags)
{
	int val;

	val = 0;
	if (flags & MSG_TSTAMP_ANY) {
		if (flags & MSG_TSTAMP)
			val |= SOF_TIMESTAMPING_TX_SOFTWARE;
		if (flags & MSG_TSTAMP_ENQ)
			val |= SOF_TIMESTAMPING_TX_SCHED;
		if (flags & MSG_TSTAMP_ACK)
			val |= SOF_TIMESTAMPING_TX_ACK;

		val |= SOF_TIMESTAMPING_OPT_ID;

		flags &= ~MSG_TSTAMP_ANY;
	}

#if 0
	if (tstamp_no_payload)
		val |= SOF_TIMESTAMPING_OPT_TX_NO_PAYLOAD;
#endif

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
		       (char *) &val, sizeof(val)))
		error(1, 0, "setsockopt");

	return flags;
}

static void do_test(int family, unsigned int flags)
{
	char *buf;
	int fd, i, val, total_len;

	if (family == IPPROTO_IPV6 && cfg_proto != SOCK_STREAM) {
		/* due to lack of checksum generation code */
		fprintf(stderr, "test: skipping datagram over IPv6\n");
		return;
	}

	total_len = payload_len;
	if (cfg_proto == SOCK_RAW) {
		total_len += sizeof(struct udphdr);
		if (cfg_ipproto == IPPROTO_RAW)
			total_len += sizeof(struct iphdr);
	}

	buf = malloc(total_len);
	if (!buf)
		error(1, 0, "malloc");

	fd = socket(family, cfg_proto, cfg_ipproto);
	if (fd < 0)
		error(1, errno, "socket");

	if (cfg_proto == SOCK_STREAM) {
		val = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			       (char*) &val, sizeof(val)))
			error(1, 0, "setsockopt no nagle");

		if (family == PF_INET) {
			if (connect(fd, (void *) &daddr, sizeof(daddr)))
				error(1, errno, "connect ipv4");
		} else {
			if (connect(fd, (void *) &daddr6, sizeof(daddr6)))
				error(1, errno, "connect ipv6");
		}
	}

	flags = setsockopt_ts(fd, flags);

	for (i = 0; i < NUM_RUNS; i++) {
		memset(&ts_prev, 0, sizeof(ts_prev));
		memset(buf, 'a' + i, total_len);
		buf[total_len - 2] = '\n';
		buf[total_len - 1] = '\0';

		if (cfg_proto == SOCK_RAW) {
			struct udphdr *udph;
			struct iphdr *iph;
			int off = 0;

			if (cfg_ipproto == IPPROTO_RAW) {
				iph = (void *) buf;

				memset(iph, 0, sizeof(*iph));
				iph->ihl      = 5;
				iph->version  = 4;
				iph->ttl      = 2;
				iph->daddr    = daddr.sin_addr.s_addr;
				iph->protocol = IPPROTO_UDP;
				/* kernel writes saddr, csum, len */

				off = sizeof(*iph);
			}

			udph = (void *) buf + off;
			udph->source = ntohs(9000); 	/* random spoof */
			udph->dest   = ntohs(dest_port);
			udph->len    = ntohs(sizeof(*udph) + payload_len);
			udph->check  = 0;	/* not allowed for IPv6 */
		}

		gettimeofday(&tv, NULL);
		if (cfg_proto != SOCK_STREAM) {
			if (family == PF_INET)
				val = sendto(fd, buf, total_len, flags, (void *) &daddr, sizeof(daddr));
			else
				val = sendto(fd, buf, total_len, flags, (void *) &daddr6, sizeof(daddr6));
		} else {
			val = send(fd, buf, payload_len, flags);
		}
		if (val != total_len)
			error(1, errno, "send");

		usleep(50 * 1000);

		print_timestamp_usr();

		__poll(fd);
		while (!recv_errmsg(fd)) {}
	}

	if (close(fd))
		error(1, errno, "close");

	free(buf);
	usleep(400 * 1000);
}

static void __attribute__((noreturn)) usage(const char *filepath)
{
	fprintf(stderr, "\nUsage: %s [options] hostname\n"
			"\nwhere options are:\n"
			"  -4:   only IPv4\n"
			"  -6:   only IPv6\n"
			"  -h:   show this message\n"
			"  -l N: send N bytes at a time\n"
			"  -n:   no payload on tstamp\n"
			"  -r:   use raw\n"
			"  -R:   use raw (IP_HDRINCL)\n"
			"  -p N: connect to port N\n"
			"  -u:   use udp\n",
			filepath);
	exit(1);
}

static void parse_opt(int argc, char **argv)
{
	int proto_count = 0;
	char c;

	while ((c = getopt(argc, argv, "46hl:np:rRu")) != -1) {
		switch (c) {
		case '4':
			do_ipv6 = 0;
			break;
		case '6':
			do_ipv4 = 0;
			break;
		case 'r':
			proto_count++;
			cfg_proto = SOCK_RAW;
			cfg_ipproto = IPPROTO_UDP;
			break;
		case 'R':
			proto_count++;
			cfg_proto = SOCK_RAW;
			cfg_ipproto = IPPROTO_RAW;
			break;
		case 'u':
			proto_count++;
			cfg_proto = SOCK_DGRAM;
			cfg_ipproto = IPPROTO_UDP;
			break;
		case 'l':
			payload_len = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			tstamp_no_payload = 1;
			break;
		case 'p':
			dest_port = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (cfg_proto != SOCK_STREAM && payload_len > 1472)
		error(1, 0, "udp packet might exceed expected MTU");
	if (!do_ipv4 && !do_ipv6)
		error(1, 0, "pass -4 or -6, not both");
	if (proto_count > 1)
		error(1, 0, "pass -r, -R or -u, not multiple");

	if (optind != argc - 1)
		error(1, 0, "missing required hostname argument");
}

static void resolve_hostname(const char *hostname)
{
	struct addrinfo *addrs, *cur;
	int have_ipv4 = 0, have_ipv6 = 0;

	if (getaddrinfo(hostname, NULL, NULL, &addrs))
		error(1, errno, "getaddrinfo");

	cur = addrs;
	while (cur && !have_ipv4 && !have_ipv6) {
		if (!have_ipv4 && cur->ai_family == AF_INET) {
			memcpy(&daddr, cur->ai_addr, sizeof(daddr));
			daddr.sin_port = htons(dest_port);
			have_ipv4 = 1;
		}
		else if (!have_ipv6 && cur->ai_family == AF_INET6) {
			memcpy(&daddr6, cur->ai_addr, sizeof(daddr6));
			daddr6.sin6_port = htons(dest_port);
			have_ipv6 = 1;
		}
		cur = cur->ai_next;
	}
	if (addrs)
		freeaddrinfo(addrs);

	do_ipv4 &= have_ipv4;
	do_ipv6 &= have_ipv6;
}

static void do_main(int family)
{
	fprintf(stderr, "family:       %s\n",
			family == PF_INET ? "INET" : "INET6");

	fprintf(stderr, "test SND\n");
	do_test(family, MSG_TSTAMP);

	fprintf(stderr, "test ENQ\n");
	do_test(family, MSG_TSTAMP_ENQ);

	fprintf(stderr, "test ENQ + SND\n");
	do_test(family, MSG_TSTAMP_ENQ | MSG_TSTAMP);

	if (cfg_proto == SOCK_STREAM) {
		fprintf(stderr, "\ntest ACK\n");
		do_test(family, MSG_TSTAMP_ACK);

		fprintf(stderr, "\ntest SND + ACK\n");
		do_test(family, MSG_TSTAMP | MSG_TSTAMP_ACK);

		fprintf(stderr, "\ntest ENQ + SND + ACK\n");
		do_test(family, MSG_TSTAMP_ENQ | MSG_TSTAMP | MSG_TSTAMP_ACK);
	}
}

const char *sock_names[] = { NULL, "TCP", "UDP", "RAW" };

int main(int argc, char **argv)
{
	parse_opt(argc, argv);
	resolve_hostname(argv[argc - 1]);

	fprintf(stderr, "protocol:     %s\n", sock_names[cfg_proto]);
	fprintf(stderr, "payload:      %u\n", payload_len);
	fprintf(stderr, "server port:  %u\n", dest_port);
	fprintf(stderr, "\n");

	if (do_ipv4)
		do_main(PF_INET);
	if (do_ipv6)
		do_main(PF_INET6);

	return 0;
}
