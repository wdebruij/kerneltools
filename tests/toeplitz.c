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
 */

/* Toeplitz test
 *
 * 1. Read packets and their rx_hash using PF_PACKET/TPACKET_V3
 * 2. Compute the rx_hash in software based on the packet contents
 * 3. Compare the two
 *
 * Optionally, if '-C $rx_irq_cpu_list' is given, also
 *
 * 4. Identify the cpu on which the packet arrived with PACKET_FANOUT_CPU
 * 5. Compute the rxqueue that RSS would select based on this rx_hash
 * 6. Using the $rx_irq_cpu_list map, identify the arriving cpu based on rxq irq
 * 7. Compare the cpus from 4 and 6
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define TOEPLITZ_KEY_MIN_LEN	40
#define TOEPLITZ_KEY_MAX_LEN	60

#define TOEPLITZ_STR_LEN(K)	((K * 3) - 1)	/* hex encoded: AA:BB:CC:...:ZZ */
#define TOEPLITZ_STR_MIN_LEN	TOEPLITZ_STR_LEN(TOEPLITZ_KEY_MIN_LEN)
#define TOEPLITZ_STR_MAX_LEN	TOEPLITZ_STR_LEN(TOEPLITZ_KEY_MAX_LEN)

#define FOUR_TUPLE_MAX_LEN	((sizeof(struct in6_addr) * 2) + (sizeof(uint16_t) * 2))

#define MAX_CPUS 256		/* real constraint is PACKET_FANOUT_MAX */

/* configuration options (cmdline arguments) */
static uint16_t cfg_dport =	8000;
static int cfg_family =		AF_INET6;
static char *cfg_ifname =	"eth0";
static int cfg_num_queues;
static bool cfg_sink;
static int cfg_type =		SOCK_STREAM;
static int cfg_timeout_msec =	1000;
static bool cfg_verbose;

/* global vars */
static int num_cpus;
static int ring_block_nr;
static int ring_block_sz;

/* stats */
static int frames_received;
static int frames_error;

#define log_verbose(args...)	do { if (cfg_verbose) fprintf(stderr, args); } while (0)

/* tpacket ring */
struct ring_state {
	int fd;
	char *mmap;
	int idx;
	int cpu;
};

static unsigned int rx_irq_cpus[MAX_CPUS];	/* map from rxq to cpu */
static unsigned char toeplitz_key[TOEPLITZ_KEY_MAX_LEN];
static struct ring_state rings[MAX_CPUS];

static inline uint32_t toeplitz(const unsigned char *four_tuple,
				const unsigned char *key)
{
	int i, bit, ret = 0;
	uint32_t key32;

	key32 = ntohl(*((uint32_t *) key));
	key += 4;

	for (i = 0; i < FOUR_TUPLE_MAX_LEN; i++) {
		for (bit = 7; bit >= 0; bit--) {
			if (four_tuple[i] & (1 << bit))
				ret ^= key32;

			key32 <<= 1;
			key32 |= !!(key[0] & (1 << bit));
		}
		key++;
	}

	return ret;
}

/* Compare computed cpu with arrival cpu from packet_fanout_cpu */
static void verify_rss(uint32_t rx_hash, int cpu)
{
	int queue = rx_hash % cfg_num_queues;

	log_verbose(" rxq %d (cpu %d)", queue, rx_irq_cpus[queue]);
	if (rx_irq_cpus[queue] != cpu) {
		log_verbose(". error: cpu mismatch (%d)", cpu);
		frames_error++;
	}
}

/* Compare computed rxhash with rxhash received from tpacket_v3 */
static void verify_rxhash(char *pkt, uint32_t rx_hash, int cpu)
{
	unsigned char four_tuple[FOUR_TUPLE_MAX_LEN] = {0};
	uint32_t rx_hash_sw;

	if (cfg_family == AF_INET)
		memcpy(four_tuple, pkt + offsetof(struct iphdr, saddr),
		       (sizeof(struct in_addr) * 2) + (sizeof(uint16_t) * 2));
	else
		memcpy(four_tuple, pkt + offsetof(struct ip6_hdr, ip6_src),
		       (sizeof(struct in6_addr) * 2) + (sizeof(uint16_t) * 2));
	
	rx_hash_sw = toeplitz(four_tuple, toeplitz_key);

	if (rx_hash != rx_hash_sw) {
		log_verbose("cpu %d: rx_hash 0x%x != expected 0x%x\n",
			    cpu, rx_hash, rx_hash_sw);
		frames_error++;
		return;
	}

	log_verbose("cpu %d: rx_hash 0x%08x", cpu, rx_hash);
	if (cfg_num_queues)
		verify_rss(rx_hash, cpu);
	log_verbose("\n");
}

static char * recv_frame(struct ring_state *ring, char *frame) {
	struct tpacket3_hdr *hdr = (void *)frame;

	if (hdr->hv1.tp_rxhash)
		verify_rxhash(frame + hdr->tp_net, hdr->hv1.tp_rxhash,
			      ring->cpu);

	return frame + hdr->tp_next_offset;
}

/* A single TPACKET_V3 block can hold multiple frames */
static void recv_block(struct ring_state *ring) {
	struct tpacket_block_desc *block;
	char *frame;
	int i;

	block = (void *) (ring->mmap + ring->idx * ring_block_sz);
	if (!(block->hdr.bh1.block_status & TP_STATUS_USER))
		return;

	frame = (char *) block;
	frame += block->hdr.bh1.offset_to_first_pkt;

	for (i = 0; i < block->hdr.bh1.num_pkts; i++) {
		frame = recv_frame(ring, frame);
		frames_received++;
	}

	block->hdr.bh1.block_status = TP_STATUS_KERNEL;
	ring->idx = (ring->idx + 1) % ring_block_nr;
}

/* simple test: sleep once unconditionally and then process all rings */
static void process_rings(void)
{
	int i;

	usleep(1000 * cfg_timeout_msec);

	for (i = 0; i < num_cpus; i++)
		recv_block(&rings[i]);

	fprintf(stderr, "count: pass=%u fail=%u\n",
		frames_received - frames_error, frames_error);
}

static char * setup_ring(int fd)
{
	struct tpacket_req3 req3 = {0};
	void *ring;

	req3.tp_retire_blk_tov = cfg_timeout_msec;
	req3.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

	req3.tp_frame_size = 2048;
	req3.tp_frame_nr = 1 << 10;
	req3.tp_block_nr = 2;

	req3.tp_block_size = req3.tp_frame_size * req3.tp_frame_nr;
	req3.tp_block_size /= req3.tp_block_nr;

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req3, sizeof(req3)))
		error(1, errno, "setsockopt PACKET_RX_RING");

	ring_block_sz = req3.tp_block_size;
	ring_block_nr = req3.tp_block_nr;

	ring = mmap(0, req3.tp_block_size * req3.tp_block_nr,
		    PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_LOCKED | MAP_POPULATE, fd, 0);
	if (ring == MAP_FAILED)
		error(1, 0, "mmap failed");

	return ring;
}

static void __set_filter(int fd, int off_proto, uint8_t proto, int off_dport)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PACKET_HOST, 0, 4),
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, off_proto),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, proto, 0, 2),
		BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, off_dport),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, cfg_dport, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, 0),
		BPF_STMT(BPF_RET + BPF_K, 0xFFFF),
	};
	struct sock_fprog prog = {};

	prog.filter = filter;
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		error(1, errno, "setsockopt filter");
}

/* filter on transport protocol and destination port */
static void set_filter(int fd)
{
	const int off_dport = offsetof(struct tcphdr, dest);	/* same for udp */
	uint8_t proto;

	proto = cfg_type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
	if (cfg_family == AF_INET)
		__set_filter(fd, offsetof(struct iphdr, protocol), proto,
				sizeof(struct iphdr) + off_dport);
	else
		__set_filter(fd, offsetof(struct ip6_hdr, ip6_nxt), proto,
				sizeof(struct ip6_hdr) + off_dport);
}

/* drop everything: used temporarily during setup */
static void set_filter_null(int fd)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct sock_fprog prog = {};

	prog.filter = filter;
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		error(1, errno, "setsockopt filter");
}

static int create_ring(char **ring)
{
	struct sockaddr_ll ll = { 0 };
	int fd, val;

	fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket creation failed");

	val = TPACKET_V3;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)))
		error(1, errno, "setsockopt PACKET_VERSION");
	*ring = setup_ring(fd);

	/* block packets until all rings are added to the fanout group:
	 * else packets can arrive during setup and get misclassified
	 */
	set_filter_null(fd);

	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex(cfg_ifname);
	ll.sll_protocol = cfg_family == AF_INET ? htons(ETH_P_IP) :
						  htons(ETH_P_IPV6);
	if (bind(fd, (void *)&ll, sizeof(ll)))
		error(1, errno, "bind");

	/* must come after bind: verifies all programs in group match */
	val = (PACKET_FANOUT_CPU << 16) | 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &val, sizeof(val)))
		error(1, errno, "setsockopt PACKET_FANOUT cpu");
	return fd;
}

/* setup inet(6) socket to blackhole the test traffic, if arg '-s' */
static int setup_sink(void)
{
	int fd, val;

	fd = socket(cfg_family, cfg_type, 0);
	if (fd == -1)
		error(1, errno, "socket %d.%d", cfg_family, cfg_type);

	val = 1 << 20;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &val, sizeof(val)))
		error(1, errno, "setsockopt rcvbuf");

	return fd;
}

static void setup_rings(void)
{
	int i;

	for (i = 0; i < num_cpus; i++) {
		rings[i].cpu = i;
		rings[i].fd = create_ring(&rings[i].mmap);
	}

	/* accept packets once all rings in the fanout group are up */
	for (i = 0; i < num_cpus; i++)
		set_filter(rings[i].fd);
}

static void cleanup_rings(void)
{
	int i;

	for (i = 0; i < num_cpus; i++) {
		if (munmap(rings[i].mmap, ring_block_nr * ring_block_sz))
			error(1, errno, "munmap");
		if (close(rings[i].fd))
			error(1, errno, "close");
	}
}

static void parse_cpulist(const char *arg)
{
	do {
		rx_irq_cpus[cfg_num_queues++] = strtol(arg, NULL, 10);

		arg = strchr(arg, ',');
		if (!arg)
			break;
		arg++;			// skip ','
	} while (1);
}

static void show_cpulist(void)
{
	int i;

	for (i = 0; i < cfg_num_queues; i++)
		fprintf(stderr, "rxq %d: cpu %d\n", i, rx_irq_cpus[i]);
}

static void parse_toeplitz_key(char *str, int slen, unsigned char *key)
{
	int i, ret, off;

	if (slen < TOEPLITZ_STR_MIN_LEN ||
	    slen > TOEPLITZ_STR_MAX_LEN + 1)
		error(1, 0, "invalid toeplitz key\n");

	for (i = 0, off = 0; off < slen; i++, off += 3) {
		ret = sscanf(str + off, "%hhx", &key[i]);
		if (ret != 1)
			error(1, 0, "parse error at key index %d off %d len %d\n", i, off, slen);
	}
}

static void parse_opts(int argc, char **argv)
{
	static struct option long_options[] = {
	    {"dport",	required_argument, 0, 'd'},
	    {"cpus",	required_argument, 0, 'C'},
	    {"key",	required_argument, 0, 'k'},
	    {"iface",	required_argument, 0, 'i'},
	    {"ipv4",	no_argument, 0, '4'},
	    {"ipv6",	no_argument, 0, '6'},
	    {"sink",	no_argument, 0, 's'},
	    {"tcp",	no_argument, 0, 't'},
	    {"timeout",	required_argument, 0, 'T'},
	    {"udp",	no_argument, 0, 'u'},
	    {"verbose",	no_argument, 0, 'v'},
	    {0, 0, 0, 0}
	};
	bool have_toeplitz = false;
	int index, c;

	while ((c = getopt_long(argc, argv, "46C:d:i:k:n:stT:u:v", long_options, &index)) != -1) {
		switch (c) {
		case '4':
			cfg_family = AF_INET;
			break;
		case '6':
			cfg_family = AF_INET6;
			break;
		case 'C':
			parse_cpulist(optarg);
			break;
		case 'd':
			cfg_dport = strtol(optarg, NULL, 0);
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'k':
			parse_toeplitz_key(optarg, strlen(optarg),
					   toeplitz_key);
			have_toeplitz = true;
			break;
		case 's':
			cfg_sink = true;
			break;
		case 't':
			cfg_type = SOCK_STREAM;
			break;
		case 'T':
			cfg_timeout_msec = strtol(optarg, NULL, 0);
			break;
		case 'u':
			cfg_type = SOCK_DGRAM;
			break;
		case 'v':
			cfg_verbose = true;
			break;

		default:
			error(1, 0, "unknown option %c", optopt);
			break;
		}
	}

	if (!have_toeplitz)
		error(1, 0, "Must supply rss key ('-k')");

	num_cpus = get_nprocs();
	if (num_cpus > MAX_CPUS)
		error(1, 0, "increase MAX_CPUS");

	if (cfg_verbose)
		show_cpulist();
}

int main(int argc, char **argv)
{
	const int min_tests = 10;
	int fd_sink;

	parse_opts(argc, argv);

	if (cfg_sink)
		fd_sink = setup_sink();

	setup_rings();
	process_rings();
	cleanup_rings();

	if (cfg_sink && close(fd_sink))
		error(1, errno, "close sink");

	if (frames_received < min_tests)
		error(1, 0, "too few frames for verification");

	return frames_error;
}
