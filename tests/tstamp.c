// SPDX-License-Identifier: GPL-2.0

/* Test SO_TIMESTAMPING */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static bool cfg_do_hw;
static bool cfg_do_sw;

static bool cfg_do_tx = true;
static bool cfg_error_encountered;

static int cfg_family = PF_INET6;
static int cfg_type = SOCK_STREAM;

static int cfg_num_pkt = 4;
const char cfg_payload[] = "a";
static uint16_t cfg_port = 8000;

static uint64_t ts_hw_prev;
static uint64_t ts_sw_prev;

static struct sockaddr *cfg_addr;
static socklen_t cfg_alen;
static struct sockaddr_in cfg_addr4 = {
	.sin_family = AF_INET,
};

static struct sockaddr_in6 cfg_addr6 = {
	.sin6_family = AF_INET6,
};

static uint64_t tstamp_u64(struct timespec *ts)
{
	return (ts->tv_sec * 1000ULL * 1000 * 1000) + ts->tv_nsec;
}

static void do_wait_tstamp(int fd, int event)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = event;

	ret = poll(&pfd, 1, 500);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		error(1, 0, "poll: timeout");

	if (!(pfd.revents & event))
		error(1, 0, "poll: revents 0x%x\n", pfd.revents);
}

static void do_recv_tstamp(int fd, int flags)
{
	char ctrl[CMSG_SPACE(sizeof(struct scm_timestamping)) +
		  CMSG_SPACE(sizeof(struct sock_extended_err)) +
		  CMSG_SPACE(sizeof(struct sockaddr_in6))] = {0};
	const char *dir = cfg_do_tx ? "tx" : "rx";
	struct scm_timestamping *tss = NULL;
	uint64_t ts, ts_hw = 0, ts_sw = 0;
	char rxbuf[sizeof(cfg_payload)];
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

	while ((cfg_do_hw && !ts_hw) ||
	       (cfg_do_sw && !ts_sw) ||
	       (!cfg_do_tx && count < 1)) {
		do_wait_tstamp(fd, cfg_do_tx ? POLLERR : POLLIN);

		ret = recvmsg(fd, &msg, flags);
		if (ret == -1 && errno == EAGAIN)
			continue;
		if (ret == -1)
			error(1, errno, "recvmsg");

		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level == SOL_SOCKET &&
			    cm->cmsg_type == SCM_TIMESTAMPING) {
				tss = (void *) CMSG_DATA(cm);
				ts = tstamp_u64(&tss->ts[0]);
				if (ts) {
					fprintf(stderr, "%s.sw: %"PRIu64"\n",
						dir, ts);
					ts_sw = ts;
				}
				ts = tstamp_u64(&tss->ts[2]);
				if (ts) {
					fprintf(stderr, "%s.hw: %"PRIu64"\n",
						dir, ts);
					ts_hw = ts;
				}
			}
		}
		count++;
	}

	/* Detect two kinds of broken timestamps:
	 * - constant values, e.g., if device clock is not running
	 * - smaller values, e.g., if counter wraps with short cycle
	 *   (~20b descriptor fields are common but should be extended to 64b)
	 */
	if (ts_sw) {
		if (ts_sw <= ts_sw_prev) {
			fprintf(stderr, "ERR: sw <= prev: %"PRIu64"\n",
					ts_sw_prev);
			cfg_error_encountered = true;
		}
		ts_sw_prev = ts_sw;
	}
	if (ts_hw) {
		if (ts_hw <= ts_hw_prev) {
			fprintf(stderr, "ERR: hw <= prev: %"PRIu64"\n",
					ts_hw_prev);
			cfg_error_encountered = true;
		}
		ts_hw_prev = ts_hw;
	}
}

static void do_test_once(int fd)
{
	int ret;

	if (cfg_do_tx) {
		ret = write(fd, cfg_payload, sizeof(cfg_payload));
		if (ret == -1)
			error(1, errno, "write");
		if (ret != sizeof(cfg_payload))
			error(1, 0, "write: %d != %lu\n",
			      ret, sizeof(cfg_payload));
		usleep(400 * 1000);
	}

	do_recv_tstamp(fd, cfg_do_tx ? MSG_ERRQUEUE : 0);
}

static void do_test(int fd)
{
	int i;

	for (i = 0; i < cfg_num_pkt; i++)
		do_test_once(fd);
}

static void parse_opts(int argc, char **argv)
{
	const char *str_addr;
	int ret, c;

	while ((c = getopt(argc, argv, "46D:hn:RstTu")) != -1) {
		switch (c) {
		case '4':
			cfg_family = PF_INET;
			break;
		case '6':
			cfg_family = PF_INET6;
			break;
		case 'D':
			str_addr = optarg;
			break;
		case 'h':
			cfg_do_hw = true;
			break;
		case 'n':
			cfg_num_pkt = strtol(optarg, NULL, 0);
			break;
		case 'R':
			cfg_do_tx = false;
			break;
		case 's':
			cfg_do_sw = true;
			break;
		case 't':
			cfg_type = SOCK_STREAM;
			break;
		case 'T':
			cfg_do_tx = true;
			break;
		case 'u':
			cfg_type = SOCK_DGRAM;
			break;
		default:
			error(1, 0, "unknown option %c\n", c);
		}
	}

	if (!str_addr)
		error(1, 0, "-D <addr> is mandatory");

	if (cfg_family == PF_INET) {
		cfg_addr = (struct sockaddr *)&cfg_addr4;
		cfg_alen = sizeof(cfg_addr4);
		cfg_addr4.sin_port = htons(cfg_port);
		ret = inet_pton(PF_INET, str_addr, &cfg_addr4.sin_addr);
	} else {
		cfg_addr = (struct sockaddr *)&cfg_addr6;
		cfg_alen = sizeof(cfg_addr6);
		cfg_addr6.sin6_port = htons(cfg_port);
		ret = inet_pton(PF_INET6, str_addr, &cfg_addr6.sin6_addr);
	}
	if (ret != 1)
		error(1, 0, "address parse error: %s", str_addr);
}

int main(int argc, char **argv)
{
	int fd, val = 0, one = 1, ret;
	int ts_sw = 0, ts_hw = 0;

	parse_opts(argc, argv);

	fd = socket(cfg_family, cfg_type, 0);
	if (fd == -1)
		error(1, errno, "socket");

	if (cfg_do_tx) {
		ret = connect(fd, cfg_addr, cfg_alen);
		if (ret)
			error(1, errno, "connect");

		if (cfg_type == SOCK_STREAM &&
		    setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)))
			error(1, errno, "setsockopt nagle");

		ts_sw = SOF_TIMESTAMPING_TX_SOFTWARE;
		ts_hw = SOF_TIMESTAMPING_TX_HARDWARE;
	} else {
		if (cfg_type == SOCK_STREAM &&
		    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
			error(1, errno, "setsockopt reuse");

		ret = bind(fd, cfg_addr, cfg_alen);
		if (ret)
			error(1, errno, "bind");

		if (cfg_type == SOCK_STREAM) {
			int fd_listen = fd;

			if (listen(fd, 1))
				error(1, errno, "listen");
			fd = accept(fd_listen, NULL, NULL);
			if (fd == -1)
				error(1, errno, "accept");
			if (close(fd_listen))
				error(1, errno, "close listen");
		}

		ts_sw = SOF_TIMESTAMPING_RX_SOFTWARE;
		ts_hw = SOF_TIMESTAMPING_RX_HARDWARE;
	}

	val = SOF_TIMESTAMPING_OPT_TSONLY;

	if (cfg_do_sw)
		val |= SOF_TIMESTAMPING_SOFTWARE | ts_sw;
	if (cfg_do_hw)
		val |= SOF_TIMESTAMPING_RAW_HARDWARE | ts_hw;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val)))
		error(1, errno, "setsockopt timestamping");

	do_test(fd);

	if (close(fd))
		error(1, errno, "close");

	if (cfg_error_encountered)
		error(1, 0, "exiting with errors");

	return 0;
}

