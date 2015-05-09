/*
 * Copyright 2015 Google Inc.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * bench_rollover: stress test the Linux kernel PF_PACKET rollover feature.
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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_NUM_SOCK	64
#define DFLT_NUM_SOCK	8

#define RING_NUM_FRAMES 1024
#define RING_FRAME_LEN	4096

#ifndef PACKET_ROLLOVER_STATS
#define PACKET_ROLLOVER_STATS	21

struct tpacket_rollover_stats {
	unsigned long tp_all;
	unsigned long tp_huge;
	unsigned long tp_failed;
};
#endif

static bool do_stop;

static int  cfg_num_sock = DFLT_NUM_SOCK;
static bool cfg_use_ring;
static int  cfg_ratelimit_ms;
static bool cfg_stats_rollover;
static bool cfg_verbose;

static void setcpu(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask))
		error(1, errno, "sched.%d", cpu);
}

static void bindtodev(int cpu, int fd, const char *dev)
{
	struct sockaddr_ll addr = {};
	static int ifindex;

	if (!ifindex)
		ifindex = if_nametoindex(dev);
	if (!ifindex)
		error(1, errno, "if_nametoindex.%s", dev);

	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_halen = ETH_ALEN;
	if (bind(fd, (void *) &addr, sizeof(addr)))
		error(1, errno, "bind.%d", cpu);
}

static void sighandler(int sig)
{
	do_stop = true;
}

static char *setrxring(int fd)
{
	struct tpacket_req req = {
		.tp_block_size = RING_FRAME_LEN,
		.tp_frame_size = RING_FRAME_LEN,
		.tp_block_nr   = RING_NUM_FRAMES,
		.tp_frame_nr   = RING_NUM_FRAMES,
	};
	char *ring;
	int val = TPACKET_V2;

	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)))
		error(1, errno, "setsockopt version");
	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)))
		error(1, errno, "setsockopt ring");

	ring = mmap(0, req.tp_block_size * req.tp_block_nr,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ring)
		error(1, errno, "setsockopt mmap");

	return ring;
}

int reader(int cpu, int fd, char *ring)
{
	struct tpacket2_hdr *hdr;
	struct tpacket_stats tpstats;
	struct tpacket_rollover_stats rstats;
	struct pollfd pfd;
	char buf[ETH_FRAME_LEN];
	unsigned long packets = 0;
	socklen_t slen;
	int ret, index = 0;

	setcpu(cpu);

	hdr = (void *) ring;
	while (!do_stop) {
		if (ring) {
			int budget = RING_NUM_FRAMES;
			while (hdr->tp_status & TP_STATUS_USER && budget--) {
				memcpy(buf, ((void *) hdr) + hdr->tp_net,
				       ETH_FRAME_LEN /* add some copy cost */);
				hdr->tp_status = TP_STATUS_KERNEL;

				packets++;
				index++;
				if (index == RING_NUM_FRAMES)
					index = 0;

				hdr = (void *) ((unsigned long) ring) +
					       (index * RING_FRAME_LEN);

				if (cfg_ratelimit_ms &&
				    (packets % (cfg_ratelimit_ms / 10)) == 0)
					usleep(100);
			}
			if (do_stop)
				continue;

			pfd.fd = fd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			ret = poll(&pfd, 1, 100);
		} else {
			 ret = read(fd, buf, sizeof(buf));
		}
		if (ret == -1 && errno == EINTR)
			break;
		if (ret == -1)
			error(1, errno, "%s.%d", ring ? "poll" : "read", cpu);
		if (!ring)
			packets++;
	}

	slen = sizeof(tpstats);
	if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS,
		       &tpstats, &slen))
		error(1, errno, "packetstat.%d", cpu);

	if (cfg_stats_rollover) {
		slen = sizeof(rstats);
		if (getsockopt(fd, SOL_PACKET, PACKET_ROLLOVER_STATS,
			       &rstats, &slen))
			error(1, errno, "rolloverstat.%d", cpu);
	} else {
		memset(&rstats, 0, sizeof(rstats));
	}

	if (packets) {
		usleep(cpu * 4000);	/* poor man's sorting */
		fprintf(stderr, "%3d %10lu %10u %10u %10lu %10lu %10lu\n",
				cpu, packets,
				tpstats.tp_packets - tpstats.tp_drops,
				tpstats.tp_drops,
				rstats.tp_all,
				rstats.tp_huge,
				rstats.tp_failed);
	}

	if (ring && munmap(ring, RING_FRAME_LEN * RING_NUM_FRAMES))
		error(1, errno, "munmap.%d", cpu);

	if (close(fd))
		error(1, errno, "close.%d", cpu);

	return 0;
}

static void __attribute__((noreturn)) usage(const char *filepath)
{
	fprintf(stderr, "Usage: %s [-h] [-l len] [-n num] [-r] [-s] [-v]\n",
			filepath);
	exit(1);
}

static void parse_opt(int argc, char **argv)
{
	const char on[] = "ON", off[] = "OFF";
	char c;

	while ((c = getopt(argc, argv, "hl:n:rsv")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			break;
		case 'l':
			cfg_ratelimit_ms = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			cfg_num_sock = strtoul(optarg, NULL, 10);
			if (cfg_num_sock > MAX_NUM_SOCK)
				error(1, 0, "num exceeds %u\n", MAX_NUM_SOCK);
			break;
		case 'r':
			cfg_use_ring = true;
			break;
		case 's':
			cfg_stats_rollover = true;
			break;
		case 'v':
			cfg_verbose = true;
			break;
		default:
			error(1, 0, "unknown parameter %c", c);
		}
	}

	if (cfg_verbose)
		fprintf(stderr, "socks:     %d\n"
				"rate:      %d K pps\n"
				"ring:      %s\n"
				"rstat:     %s\n",
				cfg_num_sock,
				cfg_ratelimit_ms ? cfg_ratelimit_ms : -1,
				cfg_use_ring ? on : off,
				cfg_stats_rollover ? on : off);
}

int main(int argc, char **argv)
{
	static int fds[MAX_NUM_SOCK];
	static char *rings[MAX_NUM_SOCK];
	struct sigaction sig = {};
	pid_t pid, pgid;
	int i, val;

	parse_opt(argc, argv);

	pgid = getpgid(0);

	/* make recv return with EINTR */
	sig.sa_handler = sighandler;
	if (sigaction(SIGINT, &sig, NULL))
		error(1, errno, "sigaction");

	for (i = 0; i < cfg_num_sock; i++) {
		fds[i] = socket(PF_PACKET, SOCK_RAW, 0);
		if (fds[i] == -1)
			error(1, errno, "socket.%d", i);

		bindtodev(i, fds[i], "eth0");

		if (cfg_use_ring) {
			rings[i] = setrxring(fds[i]);
			memset(rings[i], 0, RING_NUM_FRAMES * RING_FRAME_LEN);
		}

		val = PACKET_FANOUT_CPU | PACKET_FANOUT_FLAG_ROLLOVER;
		val <<= 16;
		if (setsockopt(fds[i], SOL_PACKET, PACKET_FANOUT,
			       &val, sizeof(val)));
	}

	for (i = 0; i < cfg_num_sock; i++) {
		pid = fork();
		if (pid == -1)
			error(1, errno, "fork.%d", i);
		if (!pid)
			return reader(i, fds[i], rings[i]);
	}

	fprintf(stderr, "Press [Enter] to exit\n");
	getchar();

	fprintf(stderr, "cpu         rx       rx.k     drop.k   rollover     r.huge   r.failed\n");
	kill(-pgid, SIGINT);
	usleep(cfg_num_sock * 5000);
	return 0;
}

