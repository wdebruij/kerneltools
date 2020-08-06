/*
 * Copyright 2014 Google Inc.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Measure tcp latency through the kernel using pcap and nflog
 *
 * Read TCP/IP packets using pcap and nflog and calculate the
 * latency spent within traffic shaping by subtracting timestamp
 * of the first occurrence (iptables) from the timestamp of the
 * second occurrence (packet socket).
 *
 * It has two modes:
 * normal:  latency of traffic shaping from protocol layer to dev:
 *          this subtracts a tstamp in packetsock on dev (eth0)
 *          from a tstamp in the ip layer at iptables NFLOG
 * bonding: latency of traffic shaping on bonding lowerdevs:
 *          this reads packets on every device, sees the same
 *          on both bonding device (e.g., bond0) and lowerdevs.
 *
 * Testing:
 * verified correctness by adding delay at the relevant traffic
 * shaping layer with
 * `tc qdisc add dev $ETH root est 1sec 4sec netem limit 40000 delay 20ms`
 *
 * Implementation:
 * tcplate uses two datastructures:
 * - table: a hashtable to store new TCP segments and their timestamp
 * - logs: a circular buffer to store tstamp diff on second viewing
 * Logs is double buffered to allow sorting results offline.
 *
 *
 * License (GPLv2):
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
#include <limits.h>
#include <linux/if.h>
#include <linux/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "libnflog.h"
#include "libpsock.h"

static int log_len = 10000;
static int table_len = 57251;	/* prime */
static int ival = 1;
static int frame_count = (1 << 14);
static int frame_size = 128;
static int bond_mode;
static int debug_mode;
static int show_extended;
static int verbose;
static char dev[IFNAMSIZ + 1] = "eth0";
static uint8_t tos_mask = UCHAR_MAX;
static bool tos_filter = false;

/* race condition. TODO: protect */
static uint64_t collisions;
static uint64_t pktcount;
static uint64_t count_nflog;
static uint64_t count_psock;

/* double buffered list of observations */
static int64_t *logs[2];
static int log_selector;
static int log_head;
static int exit_hard;

struct table_key_full {
	__be32 ip_src;
	__be32 ip_dst;
	__be16 tcp_src;
	__be16 tcp_dst;
	__be32 seqno;
} __attribute__((packed));

union table_key {
	struct table_key_full full;
	__int128 cmp;
};

struct table_elem {
	union table_key key;
	int64_t tstamp;
};

/* not thread safe */
struct table_elem *table;

/* Show how many table elements are in use */
static int
table_scan(void)
{
	int i, used = 0;

	for (i = 0; i < table_len; i++)
	if (table[i].key.cmp)
		used++;

	return used;
}

static void
log_record(int64_t val)
{
	/* do not wrap log_head, to discern a partial from full log */
	logs[log_selector][log_head % log_len] = val;
	log_head++;
}

/* switch between double buffered logs, return number of recorded events */
static int
log_rotate(void)
{
	int old_head;

	log_selector = (log_selector + 1) & 0x1;
	old_head = log_head;
	log_head = 0;

	return old_head;
}

/* qsort comparison callback */
static int
log_compar(const void *_a, const void *_b)
{
	const int64_t *a = _a, *b = _b;
	return *a < *b ? -1 : (*a > *b ? 1 : 0);
}

static void
log_show(void)
{
	int len, matches, selector;

	matches = log_rotate();
	len = matches < log_len ? matches : log_len;
	selector = (log_selector + 1) & 0x1;

	qsort(logs[selector], len, sizeof(logs[0][0]), log_compar);
	if (len >= 100) {
		fprintf(stderr, "    %8ld %8ld %8ld",
				logs[selector][len / 2],
				logs[selector][(len * 9) / 10],
				logs[selector][(len * 99) / 100]);

		if (show_extended)
			fprintf(stderr, "           %10lu %10u %10lu %10d",
					pktcount, matches, collisions,
					table_scan());
		if (show_extended && verbose > 0)
			fprintf(stderr, " %10lu %10lu",
					count_nflog, count_psock);
		write(2, "\n", 1);
	} else {
		write(2, ".\n", 2);
	}

	collisions = 0;
	pktcount = 0;
	count_nflog = 0;
	count_psock = 0;
}

/* From "The Practice of Programming" via
 * PERL_HASH in Perl 5.005, which is GPL */
static int hash_compute(void *_key, int klen)
{
	const unsigned int multiplier = 37;
	unsigned char *cur, *key = _key;
	unsigned int h = 0;

	for (cur = key; cur - key < klen; cur++)
		h = (h * multiplier) + *cur;
	return h + (h >> 5);
}

static void
packet_process(__be32 ip_src, __be32 ip_dst,
	       __be16 tcp_src, __be16 tcp_dst,
	       __be32 seqno, int64_t tstamp,
	       int caller_type)
{
	union table_key key;
	unsigned int idx;

	key.full.ip_src = ip_src;
	key.full.ip_dst = ip_dst;
	key.full.tcp_src = tcp_src;
	key.full.tcp_dst = tcp_dst;
	key.full.seqno = seqno;

	idx = hash_compute(&key, sizeof(key));
	idx %= table_len;

	/* if key is new, insert new tstamp */
	if (!table[idx].key.cmp) {
insert:
		table[idx].key.cmp = key.cmp;
		table[idx].tstamp = tstamp;
		pktcount++;
	}
	/* if collision, record and insert */
	else if (table[idx].key.cmp != key.cmp) {
		collisions++;
		goto insert;
	}
	/* else log the diff and clear the key */
	else {
		tstamp = tstamp - table[idx].tstamp;
		if (tstamp < 0)
			tstamp = -tstamp;
		log_record(tstamp);
		table[idx].key.cmp = 0;
	}

	if (debug_mode)
		fprintf(stderr, "%s %u:%hu > %u:%hu seqno=%u time=%lu\n",
			caller_type == 0 ? "nflog" : "psock",
			ntohl(ip_src), ntohs(tcp_src),
			ntohl(ip_dst), ntohs(tcp_dst),
			ntohl(seqno), tstamp);
}

static bool
tos_match(uint8_t tos)
{
	if (!tos_filter)
		return true;

	if (tos & tos_mask)
		return true;

	if (tos == tos_mask)
		return true;

	return false;
}

static void
packet_callback(struct tpacket2_hdr *tp, void *pkt)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	eth = pkt;

	if (eth->h_proto != htons(ETH_P_IP))
		return;

	iph = pkt + sizeof(*eth);

	/* TODO: support IPv6 */
	if (iph->version != 4)
		error(1, 0, "bug in parsing ip header");

	if (iph->protocol != IPPROTO_TCP)
		return;
	if (!tos_match(iph->tos))
		return;

	tcph = ((void *) iph) + (iph->ihl << 2);
	packet_process(iph->saddr, iph->daddr,
		       tcph->source, tcph->dest,
		       tcph->seq,
		       (1000LL * 1000 * tp->tp_sec) + tp->tp_nsec / 1000,
		       1);

	count_psock++;
}

static void
nflog_callback(const void *data, unsigned int len,
	       uint64_t ts_sec, uint64_t ts_usec)
{
	const struct iphdr *iph = data;
	const struct tcphdr *tcph;

	if (!len)
		return;

	if (iph->version != 4)
		error(1, 0, "bug in parsing ip header");
	if ((iph->ihl << 2) + sizeof(*tcph) > len)
		error(1, 0, "nflog snaplen too small");

	if (iph->protocol != IPPROTO_TCP)
		return;
	if (!tos_match(iph->tos))
		return;

	tcph = ((void *) iph) + (iph->ihl << 2);
	packet_process(iph->saddr, iph->daddr,
		       tcph->source, tcph->dest,
		       tcph->seq,
		       (1000LL * 1000 * ts_sec) + ts_usec,
		       0);

	count_nflog++;
}

static void
sigalrm_handler(int signum)
{
	log_show();
	alarm(ival);
}

static void
sigint_handler(int signum)
{

	if (exit_hard)
		exit(1);

	/* first try to exit gracefully based in EINTR in poll */
	exit_hard = 1;
}

static void
__init(void)
{
	logs[0] = malloc(log_len * sizeof(logs[0][0]));
	logs[1] = malloc(log_len * sizeof(logs[0][0]));
	table = calloc(table_len, sizeof(struct table_elem));
	if (!logs[0] || !logs[1] || !table)
		error(1, 0, "alloc");
}

static void
__exit(void)
{
	free(table);
	free(logs[1]);
	free(logs[0]);
}

static void __attribute__((noreturn))
usage(const char *filepath)
{
	fprintf(stderr, "usage: %s [-bdfFhqvx] [-c count] [-i iface] [-l loglen] [-L tbllen] [-t ival]\n"
			"\n"
			"where\n"
			"  -b sets bonded mode: latency in lower device tc\n"
			"  -c sets capture queue length (in packets)\n"
			"  -d debug mode, displays individual records\n"
			"  -f filter by TOS bits (pass as base 10 or 16)\n"
			"  -h to show this message and exits\n"
			"  -i interface (default: eth0)\n"
			"  -l sets the timestamp log length\n"
			"  -L sets the tcp segment hashtable length\n"
			"  -q quiet: suppresses more output\n"
			"  -t sets the display interval (secs)\n"
			"  -v sets the verbose option\n"
			"  -x show extended stats: #matched, collisions, ..\n",
			filepath);
	exit(1);
}

static void
parse_opt(int argc, char **argv)
{
	int c;

	while ((c = getopt (argc, argv, "bc:df:hi:l:L:qt:vx")) != -1)
	{
		switch (c) {
		case 'b':
			bond_mode = 1;
			break;
		case 'c':
			frame_count = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			debug_mode = 1;
			break;
		case 'f':
			tos_mask = strtoul(optarg, NULL, 0);
			tos_filter = true;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'i':
			strncpy(dev, optarg, IFNAMSIZ);
			break;
		case 'l':
			log_len = strtoul(optarg, NULL, 10);
			break;
		case 'L':
			table_len = strtoul(optarg, NULL, 10);
			break;
		case 'q':
			if (verbose > 0)
				error(1, 0, "pass -q or -v");
			verbose = -1;
			break;
		case 't':
			ival = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			if (verbose < 0)
				error(1, 0, "pass -q or -v");
			verbose = 1;
			break;
		case 'x':
			show_extended = 1;
			break;
		}
	}

	if (verbose > 0) {
		fprintf(stderr, "mode:         %s\n", bond_mode ? "bond" : dev);
		fprintf(stderr, "log_len:      %u\n", log_len);
		fprintf(stderr, "table_len:    %u\n", table_len);
		fprintf(stderr, "frame_count:  %u\n", frame_count);
		fprintf(stderr, "frame_size:   %u\n", frame_size);
		fprintf(stderr, "interval:     %u\n", ival);
		if (tos_filter)
			fprintf(stderr, "tos mask:     0x%x\n", tos_mask);
	}
}

/* @return 1 if data ready, 0 to exit */
static int do_wait(int fd1, int fd2)
{
	struct pollfd pollset[3];
	int ret;

	pollset[0].fd = 0;
	pollset[0].events = POLLIN;
	pollset[0].revents = 0;

	pollset[1].fd = fd1;
	pollset[1].events = POLLIN;
	pollset[1].revents = 0;

	pollset[2].fd = fd2;
	pollset[2].events = POLLIN;
	pollset[2].revents = 0;

	/* minor race with entering poll(), below */
	if (exit_hard)
		return 0;

	ret = poll(pollset, fd2 >= 0 ? 3 : 2, 100);
	if (ret < 0 && errno != EINTR)
		error(1, errno, "poll()");

	if (ret > 0 && pollset[0].revents)
		return 0;

	return 1;
}

#define IPT_RULE " -m time -j NFLOG --nflog-group=10 --nflog-threshold=1"
static void __exit_nflog(void)
{
	if (verbose > 0)
		system("iptables -v -nL OUTPUT | grep NFLOG");
	if (system("iptables -D OUTPUT " IPT_RULE)) {
		error(1, 0, "error while removing log module");
	}
}

/*
 * System configuration change: insert an iptables rule.
 * Ensure rollback with atexit() (though this fails with SIGINT, ..)
 */
static void __init_nflog(void)
{
	int ret;

	ret = system("iptables -L OUTPUT | grep -q NFLOG");
	if (ret == -1)
		error(1, 0, "read iptables");
	if (WEXITSTATUS(ret) == 0)
		error(1, 0, "log module still loaded? try iptables -L");

	if (system("iptables -A OUTPUT" IPT_RULE)) {
		__exit_nflog();
		error(1, 0, "load log module");
	}
	atexit(__exit_nflog);
}

static void __main(void)
{
	struct psock ps;
	int logfd;

	memset(&ps, 0, sizeof(ps));
	ps.frame_count = frame_count;
	ps.frame_size = frame_size;
	/*
	 * in normal mode, get timestamp at ip layer and eth0 dequeue
	 * in bond mode, get timestamp at bond0 and eth0 dequeue.
	 *
	 * filter psock on eth0 if calculating latency from ip to eth0.
	 * else, do not filter to read packet on both bonding and lower
	 * dev, but disable nflog.
	 */
	if (bond_mode) {
		logfd = -1;
	} else {
		/*
		 * snaplen must be smaller than PKTLEN in nflog_read
		 * or packets that are > PKTLEN && <= snaplen are dropped
		 */
		const int snaplen = 60;

		logfd = nflog_init(snaplen);
		ps.dev = dev;
	}

	psock_init(&ps);

	while (do_wait(ps.fd, logfd)) {
		if (logfd != -1)
			while (nflog_read(logfd, nflog_callback)) {}
		while (psock_read(&ps, packet_callback)) {}
	}

	psock_exit(&ps);
	if (logfd != -1)
		nflog_exit(logfd);
}

static void
print_header(void)
{
#define MAIN_HEADER	"latency:  50       90       99 (%% us)"
#define EXTRA_HEADER	"        #total   #matches   #collis.   #tblkeys"

	fprintf(stderr, "\npress Enter to exit\n"
			"\n. indicates insufficient data\n"
			"\n");

	if (show_extended)
		fprintf(stderr, MAIN_HEADER EXTRA_HEADER "\n");
	else
		fprintf(stderr, MAIN_HEADER "\n");
}

int
main(int argc, char **argv)
{
	if (verbose >= 0)
		fprintf(stderr, "tcplate v1.2: measure traffic shaping TCP latency\n");

	parse_opt(argc, argv);

	if (verbose >= 0)
		print_header();

	__init();

	signal(SIGALRM, &sigalrm_handler);
	signal(SIGINT, &sigint_handler);

	alarm(ival);

	__init_nflog();
	__main();
	__exit();

	return 0;
}

