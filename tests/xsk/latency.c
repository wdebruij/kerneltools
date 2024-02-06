// SPDX-License-Identifier: GPL-2.0-only

/* Straightforward latency measurement tool.
 *
 * Send a packet and receive it. Take timestamps along the way.
 *
 * Closed loop testing: each request is sent only after the previous
 * requests response is received.
 *
 * Run as two-process mode with client and server processes.
 * Or as one-process mode with ToR hairpin or XDP reflection.
 *
 * Takes the following timestamps:
 * t1: process sendmsg
 * t2: kernel SOF_TIMESTAMPING_TX_SOFTWARE
 * t3: kernel SOF_TIMESTAMPING_TX_HARDWARE (not yet enabled)
 * t4: kernel SOF_TIMESTAMPING_RX_HARDWARE (not yet enabled)
 * t5: kernel SOF_TIMESTAMPING_RX_SOFTWARE
 * t6: process recvmsg
 *
 *
 * Build Prerequisites (libbpf + libxdp):
 *   git clone https://github.com/xdp-project/xdp-tools.git
 *   cd xdp-tools
 *   git submodule init && git submodule update
 *   (cd lib/libbpf/src && make -j $(nprocs))
 *   ./configure
 *   make
 *   XDPTOOLS="${PWD}"
 *   LIBBPF="${PWD}/lib/libbpf"
 *   LIBXDP="${PWD}/lib/libbpf"
 *
 *
 * Build:
 *   cd $WORKDIR
 *   clang -O2 -Wall -target bpf -I ${LIBBPF}/src -g -c latency_bpf.c -o latency_bpf.o
 *   bpftool gen skeleton latency_bpf.o > latency_bpf.skel.h
 *   gcc -static -I. -O2 -Wall -g -o latency latency.c \
 *       -L ${LIBBPF}/src -L ${LIBXDP}/src \
 *       -lxdp -lbpf -lelf -lz -lzstd -lc -lm
 *
 *
 * System setup:
 *   # optionally also boot with 'mitigations=off idle=poll'
 *   # following line is not optional(!): latency only opens 1 AF_XDP socket
 *   ethtool -L ${DEV} rx 1 tx 1
 *   ip link set dev ${DEV} mtu 1500
 *   ethtool --set-priv-flags ${DEV} header-split off
 *   ethtool -K ${DEV} gro off
 *   ethtool -C ${DEV} rx-usecs 0 adaptive-rx off adaptive-tx off tx-usecs 0
 *   echo 1 | tee /sys/devices/system/cpu/cpuASTERISK/cpuidle/ASTERISK/disable
 *
 *
 * Usage (UDP):
 *   taskset -c 1 ./latency -6 -D $CLIENT_IPV6 -S $SERVER_IPV6
 *   taskset -c 1 ./latency -6 -D $SERVER_IPV6 -S $CLIENT_IPV6 -c
 *
 * Usage (PF_PACKET):
 *   # Do not let IPPROTO_RSVP enter the stack, to avoid ICMP replies.
 *   ip6tables -I INPUT -p 46 -j DROP
 *   taskset -c 1 ./latency -6 -D $CLIENT_IPV6 -S $SERVER_IPV6 -P
 *   taskset -c 1 ./latency -6 -D $SERVER_IPV6 -S $CLIENT_IPV6 -P -c
 *
 * Usage (AF_XDP):
 *   taskset -c 1 ./latency -6 -D $CLIENT_IPV6 -S $SERVER_IPV6 -X
 *   taskset -c 1 ./latency -6 -D $SERVER_IPV6 -S $CLIENT_IPV6 -X -c
 *
 * Optionally pass -v for some extra info, and -v -v for per-packet debugging.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <errno.h>
#include <error.h>
#include <linux/errqueue.h>
#include <linux/filter.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/net_tstamp.h>
#include <math.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "latency_bpf.skel.h"


/* Avoid optimizations for tiny packets, such as copy-break.
 * Must be a macro to use in static allocs like pkt_v4.
 */
#define CFG_PAYLOAD_LEN (400)

union sockaddr_in46 {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

static union sockaddr_in46 cfg_daddr, cfg_saddr;
static char *cfg_daddr_str, *cfg_saddr_str;
static int cfg_busypoll_us;
static bool cfg_client;
static int cfg_debug;
static int cfg_duration_ms = 10000;
static char *cfg_ifname = "eth0";
static int cfg_ifindex;
static char *cfg_mac_dst, *cfg_mac_src;
static int cfg_rcvtimeo = 5;
static int cfg_sk_domain;
static int cfg_sk_family = PF_UNSPEC;
static char cfg_sk_proto = IPPROTO_RSVP;
static bool cfg_tstamp_hw;
static int cfg_verbose;
static int cfg_warmup_ms = 100;

/* Arrays to compute latency diffs */
#define NUM_TDIFFS (100 * 1000)
static uint64_t tdiffs[NUM_TDIFFS];
static uint64_t tdiffs_tx[NUM_TDIFFS];
static uint64_t tdiffs_rx[NUM_TDIFFS];

/* XDP & AF_XDP objects
 *
 * Here, an XDP BPF filter is used so the program only receive RSVP packets in
 * the XSK, and are not affected by the traffic outside of this test.
 * Additionally, the  test runs with no concurrent request / response, i.e. the
 * response must be received before the next request is sent, so there should
 * not be a spike in incoming packets, so the program does not need to reserve
 * huge sizes for the queues. Umem is split into half-half, one for the RX side
 * consisting of fill queue and RX queue, initialized to have all the frames
 * in the fill queue, and one for the TX side consisting of TX queue and
 * completion queue, initialized to have all the frames be pending (in neither
 * queues). The program will load pending frames into TX queue, while consuming
 * the completion queue into its own pending queue, which is initialized as a
 * simple ring queue. TX overhead can also be reduced by pre-initializing all
 * the TX frame contents.
 *
 * We have one XSK with its own umem for each hardware queue, and we count the
 * number of successful XSK bindings to know how many hardware queues exists.
 */

/* Single-queue here because the setup `ethtool -L eth1 combined 1` */
#define QUEUE_ID 0
#define NUM_FRAMES 16
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (2 * NUM_FRAMES * FRAME_SIZE)

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct {
		uint32_t head;
		uint32_t tail;
	} umem_tx;
	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	void *buffer;
};

static struct xsk_socket_info xsk;
static struct latency_bpf *latency_bpf;

/* With PF_PACKET, prepare the packet once and send repeatedly. */
static char pkt_v4[ETH_HLEN + sizeof(struct iphdr) + CFG_PAYLOAD_LEN];
static char pkt_v6[ETH_HLEN + sizeof(struct ipv6hdr) + CFG_PAYLOAD_LEN];

struct pkt_proto_info {
	uint16_t eth_proto;
	struct sockaddr *daddr;
	socklen_t alen;
	char *pkt;
	size_t pkt_size;
};

static struct pkt_proto_info pkt_ipv4 = {
	.eth_proto = __constant_htons(ETH_P_IP),
	.alen = sizeof(cfg_daddr.sin),
	.pkt = pkt_v4,
	.pkt_size = sizeof(pkt_v4),
};

static struct pkt_proto_info pkt_ipv6 = {
	.eth_proto = __constant_htons(ETH_P_IPV6),
	.alen = sizeof(cfg_daddr.sin6),
	.pkt = pkt_v6,
	.pkt_size = sizeof(pkt_v6),
};

static struct pkt_proto_info *cfg_proto;

static int64_t gettimeofday_ns64(void)
{
	struct timespec ts;

	if (cfg_sk_domain == PF_XDP)
		/* CLOCK_MONOTONIC to match bpf_ktime_get_ns
		 * TODO: convert to bpf_ktime_get_boot_ns */
		clock_gettime(CLOCK_MONOTONIC, &ts);
	else
		/* CLOCK_REALTIME to match SO_TIMESTAMPING */
		clock_gettime(CLOCK_REALTIME, &ts);

	return (int64_t) (ts.tv_sec * 1000UL * 1000 * 1000) + ts.tv_nsec;
}

static uint64_t timespec_to_ns64(const struct timespec *ts)
{
	return (ts->tv_sec * 1000UL * 1000 * 1000) + ts->tv_nsec;
}

static uint32_t checksum_nofold(char *data, size_t len, uint32_t sum)
{
	uint16_t *words = (uint16_t *)data;
	int i;

	for (i = 0; i < len / 2; i++)
		sum += words[i];

	if (len & 1)
		sum += ((unsigned char *)data)[len - 1];

	return sum;
}

static uint16_t checksum_fold(void *data, size_t len, uint32_t sum)
{
	sum = checksum_nofold(data, len, sum);

	while (sum > 0xFFFF)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static void init_pkt(void)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	/* init mac header */
	eth = (void *)cfg_proto->pkt;
	if (sscanf(cfg_mac_dst, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &eth->h_dest[0], &eth->h_dest[1], &eth->h_dest[2],
		   &eth->h_dest[3], &eth->h_dest[4], &eth->h_dest[5]) != 6)
		error(1, 0, "sscanf mac dst ('-M') \n");
	if (sscanf(cfg_mac_src, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &eth->h_source[0], &eth->h_source[1], &eth->h_source[2],
		   &eth->h_source[3], &eth->h_source[4], &eth->h_source[5]) != 6)
		error(1, 0, "sscanf mac src ('-m')\n");
	eth->h_proto = cfg_proto->eth_proto;

	if (cfg_sk_family == PF_INET) {
		/* init ipv4 header */
		iph = (void *)(eth + 1);

		if (inet_pton(AF_INET, cfg_daddr_str, &iph->daddr) != 1)
			error(1, 0, "ipv4 parse error: dst ('-D')");
		if (inet_pton(AF_INET, cfg_saddr_str, &iph->saddr) != 1)
			error(1, 0, "ipv4 parse error: src ('-S')");
		iph->version = 4;
		iph->ihl = 5;
		iph->tot_len = htons(sizeof(*iph) + CFG_PAYLOAD_LEN);
		iph->ttl = 8;
		iph->protocol = cfg_sk_proto;
		iph->check = 0;
		iph->check = checksum_fold(iph, sizeof(*iph), 0);
	} else {
		/* init ipv6 header */
		ip6h = (void *)(eth + 1);

		if (inet_pton(AF_INET6, cfg_daddr_str, &ip6h->daddr) != 1)
			error(1, 0, "ipv6 parse error: dst ('-D')");
		if (inet_pton(AF_INET6, cfg_saddr_str, &ip6h->saddr) != 1)
			error(1, 0, "ipv6 parse error: src ('-S')");
		ip6h->version = 6;
		ip6h->nexthdr = cfg_sk_proto;
		ip6h->payload_len = htons(CFG_PAYLOAD_LEN);
		ip6h->hop_limit = 8;
	}

	/* payload initialized as all zeroes */
}


static void pfpacket_setfilter_ipproto(int fd, char ipproto)
{
	int off_proto;

	if (cfg_sk_family == PF_INET)
		off_proto = ETH_HLEN + __builtin_offsetof(struct iphdr, protocol);
	else
		off_proto = ETH_HLEN + __builtin_offsetof(struct ipv6hdr, nexthdr);

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PACKET_HOST, 0, 2),
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, off_proto),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ipproto, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, 0),
		BPF_STMT(BPF_RET + BPF_K, 0xFFFF),
	};
	struct sock_fprog prog = {};

	prog.filter = filter;
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		error(1, errno, "setsockopt filter");
}

static void pfpacket_bind(int fd)
{
	struct sockaddr_ll laddr;
	int val;

	laddr.sll_family = AF_PACKET;
	laddr.sll_protocol = cfg_proto->eth_proto;
	laddr.sll_ifindex = cfg_ifindex;

	if (bind(fd, (void *) &laddr, sizeof(laddr)) == -1)
		error(1, 0, "packetsock bind");

	/* shorter tx path to reduce latency */
	val = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val)))
		error(1, 0, "packetsock qdisc bypass");
}

static void do_send_pfpacket(int fd, uint32_t pkt_id)
{
	uint32_t *payload = (uint32_t *)(cfg_proto->pkt + cfg_proto->pkt_size - CFG_PAYLOAD_LEN);
	int ret;

	*payload = pkt_id;

	ret = write(fd, cfg_proto->pkt, cfg_proto->pkt_size);
	if (ret != cfg_proto->pkt_size)
		error(1, errno, "write: %d\n", ret);
}

static void do_send_udp(int fd, uint32_t pkt_id)
{
	uint32_t *payload = (uint32_t *)(cfg_proto->pkt + cfg_proto->pkt_size - CFG_PAYLOAD_LEN);
	int ret;

	*payload = pkt_id;

	ret = sendto(fd, payload, CFG_PAYLOAD_LEN, 0,
		     &cfg_daddr.sa, cfg_proto->alen);
	if (ret != CFG_PAYLOAD_LEN)
		error(1, errno, "write: %d\n", ret);
}

static void do_send_xsk(int fd, uint32_t pkt_id)
{
	uint32_t idx_tx, idx_cq, *payload;
	struct xdp_desc *desc;
	const char *pkt;
	int n;

	if (xsk.umem_tx.tail == xsk.umem_tx.head)
		error(1, 0, "TX avail ring is full");
	if (xsk_ring_prod__reserve(&xsk.tx, 1, &idx_tx) != 1)
		error(1, 0, "TX ring is full");

	/* fill in tx descriptor */
	desc = xsk_ring_prod__tx_desc(&xsk.tx, idx_tx);
	desc->addr = xsk.umem_tx.tail * FRAME_SIZE;
	desc->len = cfg_proto->pkt_size;

	/* fill in pkt contents */
	pkt = xsk_umem__get_data(xsk.buffer, xsk_umem__add_offset_to_addr(desc->addr));
	payload = (uint32_t *)(pkt + cfg_proto->pkt_size - CFG_PAYLOAD_LEN);
	*payload = pkt_id;

	/* submit tx descriptor and optionally wake consumer */
	xsk_ring_prod__submit(&xsk.tx, 1);
	/* TODO: try sendto mitigation with xsk_ring_prod__needs_wakeup on TX */
	sendto(xsk_socket__fd(xsk.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	xsk.umem_tx.tail++;
	if (xsk.umem_tx.tail >= NUM_FRAMES)
		xsk.umem_tx.tail = xsk.umem_tx.tail % NUM_FRAMES;

	/* clean tx completions */
	n = xsk_ring_cons__peek(&xsk.cq, NUM_FRAMES, &idx_cq);
	if (n) {
		xsk.umem_tx.head = (xsk.umem_tx.head + n) % NUM_FRAMES;
		xsk_ring_cons__release(&xsk.cq, n);
	}

	if (cfg_verbose >= 2)
		fprintf(stderr, "%s: tx.%u umem.%u pkt=0x%08x\n",
				__func__, idx_tx, xsk.umem_tx.tail, ntohl(pkt_id));
}

static void do_send(int fd, uint32_t pkt_id)
{
	/* identify client and server on the wire */
	pkt_id &= 0xFFFFFF;
	pkt_id |= cfg_client ? 0xCC000000 : 0xDD000000;

	/* write in network byte order */
	pkt_id = htonl(pkt_id);

	switch (cfg_sk_domain) {
	case PF_XDP:
		do_send_xsk(fd, pkt_id);
		break;
	case PF_PACKET:
		do_send_pfpacket(fd, pkt_id);
		break;
	default:
		do_send_udp(fd, pkt_id);
		break;
	}

	if (cfg_verbose >= 2)
		printf("%s: id 0x%08x\n", __func__, ntohl(pkt_id));
}

static uint64_t do_recv_timestamping(const char *pre, struct msghdr *msg)
{
	struct scm_timestamping *ts;
	struct cmsghdr *cm;

	for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
		/* tx timestamps are accompanied by data. disregard that */
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_RECVERR)
			continue;

		if (cm->cmsg_level != SOL_SOCKET ||
		    cm->cmsg_type != SO_TIMESTAMPING)
			error(1, 0, "errqueue: cm %u.%u\n",
			      cm->cmsg_level, cm->cmsg_type);

		ts = (void *)CMSG_DATA(cm);

		if (cfg_debug)
			fprintf(stderr, "tstamp: %s: %lu,%lu,%lu\n",
					pre,
					timespec_to_ns64(&ts->ts[0]),
					timespec_to_ns64(&ts->ts[1]),
					timespec_to_ns64(&ts->ts[2]));

		return timespec_to_ns64(&ts->ts[0]);
	}

	error(1, 0, "%s: missing tstamp\n", __func__);
	return 0;
}

/* Poll until data is waiting.
 * Return: true if data is waiting, false on timeout.
 */
static bool do_recv_xsk_poll(uint32_t *idx_rx, uint64_t tstop)
{
	unsigned short loop = 0;
	unsigned int n;

	while (!(n = xsk_ring_cons__peek(&xsk.rx, 1, idx_rx))) {
		/* TODO: try recvfrom mitigation with xsk_ring_prod__needs_wakeup on FQ */
		if (recvfrom(xsk_socket__fd(xsk.xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL))
			error(1, errno, "recvfrom");

		/* test timeout every 64K iterations */
		if (loop++ == 0xFFFF && gettimeofday_ns64() >= tstop)
			return false;
	};

	if (n != 1)
		error(1, 0, "num_received != 1");

	return true;
}

static int64_t do_recv_xsk(uint64_t tstop)
{
	const struct xdp_desc *desc;
	uint32_t *payload, pkt_id;
	uint32_t idx_rx, idx_fq;
	char *pkt;

	if (xsk_ring_prod__reserve(&xsk.fq, 1, &idx_fq) != 1)
		error(1, 0, "FQ full");

	if (!do_recv_xsk_poll(&idx_rx, tstop))
		return -1;

	desc = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx);
	if (desc->len != cfg_proto->pkt_size)
		error(1, 0, "bad recv length: %d\n", desc->len);

	pkt = xsk_umem__get_data(xsk.buffer,
				 xsk_umem__add_offset_to_addr(desc->addr));
	payload = (uint32_t *)(pkt + cfg_proto->pkt_size - CFG_PAYLOAD_LEN);
	pkt_id = ntohl(*payload);

	if (cfg_verbose >= 2)
		fprintf(stderr, "%s: rx.%u umem.%llu pkt=0x%x\n",
				__func__, idx_rx, desc->addr / FRAME_SIZE, pkt_id);

	xsk_ring_cons__release(&xsk.rx, 1);
	*xsk_ring_prod__fill_addr(&xsk.fq, idx_fq) = xsk_umem__extract_addr(desc->addr);
	xsk_ring_prod__submit(&xsk.fq, 1);

	return pkt_id;
}

static int64_t do_recv_fd(int fd, struct msghdr *msg)
{
	const uint32_t *payload;
	int ret;

	ret = recvmsg(fd, msg, 0);
	if (ret == -1 && errno == EAGAIN)
		return -1;
	if (ret == -1)
		error(1, errno, "recvmsg");
	if (ret != (cfg_sk_domain == PF_PACKET ? cfg_proto->pkt_size : CFG_PAYLOAD_LEN))
		error(1, 0, "recvmsg: %d\n", ret);
	if (msg->msg_flags & MSG_CTRUNC)
		error(1, 0, "recvmsg: flags 0x%x\n", msg->msg_flags);

	payload = (void *)(msg->msg_iov[0].iov_base + ret - CFG_PAYLOAD_LEN);
	return ntohl(*payload);
}

static bool do_recv(int fd, struct msghdr *msg, uint32_t expected_pkt_id,
		    uint64_t tstop)
{
	int64_t ret;
	uint32_t pkt_id;

	switch (cfg_sk_domain) {
	case PF_XDP:
		ret = do_recv_xsk(tstop);
		break;
	default:
		ret = do_recv_fd(fd, msg);
		break;
	}

	/* timeout */
	if (ret == -1)
		return false;

	if (cfg_verbose >= 2)
		printf("%s: id 0x%08lx\n", __func__, ret);

	pkt_id = ret & 0x00FFFFFF;
	if (pkt_id != expected_pkt_id)
		error(1, 0, "%s: pkt id 0x%x != 0x%x\n",
		      __func__, pkt_id, expected_pkt_id);

	return true;
}

static uint64_t __attribute__((unused)) do_recv_errqueue(int fd)
{
	char control[CMSG_SPACE(sizeof(struct scm_timestamping)) +
		     CMSG_SPACE(sizeof(struct sock_extended_err)) +
		     CMSG_SPACE(sizeof(struct sockaddr_in6))];
	struct msghdr msg = {0};
	int ret;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
	if (ret == -1)
		error(1, errno, "recvmsg MSG_ERRQUEUE");
	if (msg.msg_flags & MSG_CTRUNC)
		error(1, 0, "recvmsg: flags 0x%x\n", msg.msg_flags);

	return do_recv_timestamping("tx", &msg);
}

static void do_sync_client(void)
{
	const int retry_sleep_ms = 200;
	const int retries_per_sec = 1000 / retry_sleep_ms;
	const int max_retries = cfg_rcvtimeo * retries_per_sec;
	int fd, ret, retries = 0;

	fd = socket(cfg_sk_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket sync client");

	/* If the client calls connect before the server listens,
	 * the connection will fail immediately and the call returns
	 * with ECONNREFUSED. Retry up to cfg_rcvtimeo.
	 */
	while (true) {
		ret = connect(fd, &cfg_daddr.sa, cfg_proto->alen);
		if (ret == -1 && errno != ECONNREFUSED)
			error(1, errno, "connect sync client");
		if (ret == 0)
			break;
		retries++;
		usleep(retry_sleep_ms * 1000);
		if (retries == max_retries)
			error(1, 0, "connect sync client: max_retries");
	}

	if (close(fd))
		error(1, errno, "close sync client");
}

static void do_sync_server(void)
{
	struct timeval tv = { .tv_sec = cfg_rcvtimeo };
	int fdl, fdc, one = 1;

	fdl = socket(cfg_sk_family, SOCK_STREAM, 0);
	if (fdl == -1)
		error(1, errno, "socket sync listener");

	if (setsockopt(fdl, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		error(1, errno, "setsockopt reuseaddr sync");

	if (setsockopt(fdl, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
		error(1, errno, "setsockopt so_rcvtimeo");

	if (bind(fdl, &cfg_saddr.sa, cfg_proto->alen))
		error(1, errno, "bind sync");
	if (listen(fdl, 1))
		error(1, errno, "listen sync");

	fdc = accept(fdl, NULL, NULL);
	if (fdc == -1)
		error(1, errno, "accept sync");

	if (close(fdc))
		error(1, errno, "close sync child");
	if (close(fdl))
		error(1, errno, "close sync listener");
}

static void try_parse_ip(const char *optarg, union sockaddr_in46 *output)
{
	if (cfg_sk_family == AF_INET) {
		if (inet_pton(AF_INET, optarg, &output->sin.sin_addr) != 1)
			error(1, 0, "ipv4 parse error: %s", optarg);
	} else {
		if (inet_pton(AF_INET6, optarg, &output->sin6.sin6_addr) != 1)
			error(1, 0, "ipv6 parse error: %s", optarg);
	}
}

static void parse_opts(int argc, char **argv)
{
	int c;

	/* defaults, may be overridden by getopt */
	uint16_t port = htons(8000);

	while ((c = getopt(argc, argv, "46BcD:i:l:m:M:p:PS:vw:X")) != -1) {
		switch (c) {
		case '4':
			if (cfg_sk_family == PF_INET6)
				error(1, 0, "-4 and -6 cannot both be specified");
			cfg_sk_family = PF_INET;
			cfg_proto = &pkt_ipv4;
			break;
		case '6':
			if (cfg_sk_family == PF_INET)
				error(1, 0, "-4 and -6 cannot both be specified");
			cfg_sk_family = PF_INET6;
			cfg_proto = &pkt_ipv6;
			break;
		case 'B':
			/* Expose as boolean option: no point fine-tuning */
			cfg_busypoll_us = 100;
			break;
		case 'c':
			cfg_client = true;
			break;
		case 'D':
			cfg_daddr_str = optarg;
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'l':
			cfg_duration_ms = atoi(optarg) * 1000;
			break;
		case 'm':
			cfg_mac_src = optarg;
			break;
		case 'M':
			cfg_mac_dst = optarg;
			break;
		case 'p':
			port = htons(atoi(optarg));
			break;
		case 'P':
			if (cfg_sk_domain)
				error(1, 0, "socket domain already set");
			cfg_sk_domain = PF_PACKET;
			break;
		case 'S':
			cfg_saddr_str = optarg;
			break;
		case 'v':
			cfg_verbose++;
			break;
		case 'w':
			cfg_warmup_ms = atoi(optarg) * 1000;
			break;
		case 'X':
			if (cfg_sk_domain)
				error(1, 0, "socket domain already set");
			cfg_sk_domain = PF_XDP;
			break;
		default:
			error(1, 0, "%s: parse error", argv[0]);
		}
	}

	if (cfg_sk_family == PF_UNSPEC)
		error(1, 0, "one of -4 or -6 must be specified");

	/* sk_family selects the protocol of the packets on the wire.
	 * sk_domain selects the protocol stack used to send packets.
	 */
	if (!cfg_sk_domain)
		cfg_sk_domain = cfg_sk_family;

	if (cfg_daddr_str) {
		try_parse_ip(cfg_daddr_str, &cfg_daddr);
	} else {
		if (cfg_sk_family == AF_INET)
			cfg_daddr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		else
			cfg_daddr.sin6.sin6_addr = in6addr_loopback;
	}

	if (cfg_saddr_str) {
		try_parse_ip(cfg_saddr_str, &cfg_saddr);
	} else {
		if (cfg_sk_family == AF_INET)
			cfg_daddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		else
			cfg_daddr.sin6.sin6_addr = in6addr_any;
	}

	if (cfg_sk_family == AF_INET) {
		cfg_daddr.sin.sin_family = PF_INET;
		cfg_daddr.sin.sin_port = port;
		cfg_saddr.sin.sin_family = PF_INET;
		cfg_saddr.sin.sin_port = port;
	} else {
		cfg_daddr.sin6.sin6_family = PF_INET6;
		cfg_daddr.sin6.sin6_port = port;
		cfg_saddr.sin6.sin6_family = PF_INET6;
		cfg_saddr.sin6.sin6_port = port;
	}

	if (cfg_sk_domain == PF_XDP || cfg_sk_domain == PF_PACKET) {
		if (!cfg_mac_src || !cfg_mac_dst || !cfg_saddr_str || !cfg_daddr_str)
			error(1, 0, "pf_packet needs all mac and ip addresses set");
	}

	cfg_ifindex = if_nametoindex(cfg_ifname);
	if (!cfg_ifindex)
		error(1, 0, "if_nametoindex");
}

static int cmp_int(const void *_a, const void *_b)
{
	const int *a = _a;
	const int *b = _b;

	if (*a < *b)
		return -1;
	else if (*a > *b)
		return 1;
	else
		return 0;
}

static void print_stats_array(const char *pre, uint64_t *array, int num)
{
	printf("%smin:\t\t%lu\n%smax:\t\t%lu\n%s50%%:\t\t%lu\n%s90%%:\t\t%lu\n%s99%%:\t\t%lu\n%s99.9%%:\t\t%lu\n%scount:\t\t%d\n\n",
	       pre, array[0],
	       pre, array[num - 1],
	       pre, array[num / 2],
	       pre, array[(num * 9) / 10],
	       pre, array[(num * 99) / 100],
	       pre, array[(num * 999) / 1000],
	       pre, num);
}

static int print_stats(int num)
{
	double mean, dev, stddev = 0;
	uint64_t total = 0;
	int i;

	if (num < NUM_TDIFFS) {
		printf("\nWARN: stats: insufficient datapoints (%u < %u)\n\n", num, NUM_TDIFFS);
		return 1;
	}

	if (num > NUM_TDIFFS)
		num = NUM_TDIFFS;

	for (i = 0; i < num; i++)
		total += tdiffs[i];
	mean = total / num;

	for (i = 0; i < num; i++) {
		dev = mean > tdiffs[i] ? mean - tdiffs[i] : tdiffs[i] - mean;
		dev = dev * dev;
		stddev += dev;
	}
	stddev /= num;
	stddev = sqrt(stddev);

	qsort(tdiffs, num, sizeof(tdiffs[0]), cmp_int);
	qsort(tdiffs_rx, num, sizeof(tdiffs_rx[0]), cmp_int);
	qsort(tdiffs_tx, num, sizeof(tdiffs_tx[0]), cmp_int);

	printf("mean:\t\t%f\nstddev:\t\t%f\n\n", mean, stddev);
	print_stats_array("[t2-t1]", tdiffs_tx, num);
	print_stats_array("[t3-t2]", tdiffs, num);
	print_stats_array("[t4-t3]", tdiffs_rx, num);

	return 0;
}

static int init_udp(void)
{
	int fd;

	fd = socket(cfg_sk_family, SOCK_DGRAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	/* udp server must bind to port */
	if (bind(fd, &cfg_saddr.sa, cfg_proto->alen))
		error(1, errno, "bind");

	return fd;
}

static int init_pfpacket(void)
{
	int fd;

	fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (fd == -1)
		error(1, errno, "socket");

	pfpacket_setfilter_ipproto(fd, cfg_sk_proto);
	pfpacket_bind(fd);

	return fd;
}

static void cleanup_xsk(void)
{
	bpf_xdp_detach(cfg_ifindex, XDP_FLAGS_DRV_MODE, NULL);
}

static int init_xsk(void)
{
	struct xsk_umem_config umem_cfg = {
		.fill_size = NUM_FRAMES * 2,
		.comp_size = NUM_FRAMES,
		.frame_size = FRAME_SIZE,
	};
	struct xsk_socket_config xsk_cfg = {
		.rx_size = NUM_FRAMES,
		.tx_size = NUM_FRAMES,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY,
	};
	int frame, key, fd;
	__u32 idx;

	/* Detach existing XDP if there's one, or otherwise attaching will fail */
	cleanup_xsk();

	latency_bpf = latency_bpf__open_and_load();
	if (!latency_bpf)
		error(1, errno, "bpf load");

	xsk.buffer = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!xsk.buffer)
		error(1, errno, "mmap");

	if (xsk_umem__create(&xsk.umem, xsk.buffer, UMEM_SIZE, &xsk.fq, &xsk.cq, &umem_cfg))
		error(1, errno, "xsk_umem__create");

	if (xsk_socket__create(&xsk.xsk, cfg_ifname, QUEUE_ID, xsk.umem, &xsk.rx, &xsk.tx, &xsk_cfg))
		error(1, errno, "xsk_socket__create");

	/* First half of UMEM: Initialize into pending packets, and fill contents */
	for (frame = 0; frame < NUM_FRAMES; frame++)
		memcpy(xsk_umem__get_data(xsk.buffer, frame * FRAME_SIZE),
		       cfg_proto->pkt, cfg_proto->pkt_size);
	xsk.umem_tx.head = NUM_FRAMES - 1;

	/* Second half of UMEM: Initialize into fill queue */
	if (xsk_ring_prod__reserve(&xsk.fq, NUM_FRAMES, &idx) != NUM_FRAMES)
		error(1, errno, "xsk_ring_prod__reserve");
	for (frame = 0; frame < NUM_FRAMES; frame++)
		*xsk_ring_prod__fill_addr(&xsk.fq, idx++) = (frame + NUM_FRAMES) * FRAME_SIZE;
	xsk_ring_prod__submit(&xsk.fq, NUM_FRAMES);

	key = QUEUE_ID;
	fd = xsk_socket__fd(xsk.xsk);
	if (bpf_map_update_elem(bpf_map__fd(latency_bpf->maps.xsks_map), &key, &fd, 0))
		error(1, errno, "bpf_map_update_elem");

	if (bpf_xdp_attach(cfg_ifindex,
			   bpf_program__fd(latency_bpf->progs.latency_bpf),
			   XDP_FLAGS_DRV_MODE, NULL))
		error(1, errno, "bpf_xdp_attach");

	atexit(cleanup_xsk);

	return fd;
}

int main(int argc, char **argv)
{
	char control[CMSG_SPACE(sizeof(struct scm_timestamping))];
	struct timeval tv = { .tv_sec = cfg_rcvtimeo };
	struct msghdr msg = {0};
	struct iovec iov = {0};
	int64_t tstart, t1, t2, t3, t4 = 0, tstop;
	uint64_t num_trans_warmup, num_trans = 0;
	int fd, val, idx, ret = 0;

	parse_opts(argc, argv);

	init_pkt();

	switch (cfg_sk_domain) {
	case PF_XDP:
		fd = init_xsk();
		break;
	case PF_PACKET:
		fd = init_pfpacket();
		break;
	default:
		fd = init_udp();
		break;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
		error(1, errno, "setsockopt so_rcvtimeo");

	if (cfg_busypoll_us) {
		if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL,
			       &cfg_busypoll_us, sizeof(cfg_busypoll_us)))
			error(1, errno, "setsockopt so_busy_poll");

		val = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL,
			       &val, sizeof(val)))
			error(1, errno, "setsockopt so_prefer_busy_poll");
	}

	val = SOF_TIMESTAMPING_SOFTWARE |
	      SOF_TIMESTAMPING_RX_SOFTWARE |
	      SOF_TIMESTAMPING_OPT_ID |
	      SOF_TIMESTAMPING_OPT_TSONLY;

	if (cfg_tstamp_hw)
		val |= SOF_TIMESTAMPING_RAW_HARDWARE |
		       SOF_TIMESTAMPING_RX_HARDWARE |
		       SOF_TIMESTAMPING_TX_HARDWARE;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val)))
		error(1, errno, "setsockopt so_timestamping");

	iov.iov_base = alloca(cfg_proto->pkt_size);
	iov.iov_len = cfg_proto->pkt_size;

	msg.msg_name = &cfg_daddr;
	msg.msg_namelen = cfg_proto->alen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	/* sync peers */
	if (cfg_verbose) printf("sync..\n");
	if (cfg_client)
		do_sync_client();
	else
		do_sync_server();
	if (cfg_verbose) printf("sync complete\n");

	/* warm up loop */
	if (cfg_verbose) printf("warm-up.. \n");
	tstart = gettimeofday_ns64();
	tstop = tstart + (cfg_warmup_ms * 1000UL * 1000);
	while (gettimeofday_ns64() < tstop) {
		if (cfg_client)
			do_send(fd, num_trans);
		if (do_recv(fd, &msg, num_trans, tstop) && !cfg_client)
			do_send(fd, num_trans);
		num_trans++;
	}
	num_trans_warmup = num_trans;
	if (cfg_verbose) printf("warm-up complete\n");

	/* main loop */
	tstart = gettimeofday_ns64();
	tstop = tstart + (cfg_duration_ms * 1000UL * 1000);
	do {
		t1 = gettimeofday_ns64();
		if (cfg_client)
			do_send(fd, num_trans);
		t2 = gettimeofday_ns64();
		if (!do_recv(fd, &msg, num_trans, tstop))
			break;
		t4 = gettimeofday_ns64();
		if (!cfg_client)
			do_send(fd, num_trans);
		if (cfg_sk_domain == PF_XDP)
			t3 = latency_bpf->bss->xdp_rx_timestamp;
		else
			t3 = do_recv_timestamping("rx", &msg);

		if (cfg_verbose >= 2)
			printf("tdiff=%lu us\n", (t4 - t1) / 1000);

		idx = num_trans % NUM_TDIFFS;
		tdiffs[idx] = t3 - t2 <= 0 ? 0 : t3 - t2;
		tdiffs_rx[idx] = t4 - t3;
		tdiffs_tx[idx] = t2 - t1;
		num_trans++;
	} while (t4 < tstop);

	/* TODO:
	 *  - print ever cfg_print_interval (1 sec)
	 *  - add SO_TIMESTAMPING hw
	 *  - add SO_TIMESTAMPING tx: extra column in tdiffs
	 */
	num_trans -= num_trans_warmup;
	printf("runtime_ms:\t%lu\n", (t4 - tstart) / (1000UL * 1000));
	printf("transactions:\t%lu\n", num_trans);

	if (cfg_sk_domain == PF_XDP && cfg_verbose) {
		struct xdp_statistics stats = { 0 };
		socklen_t slen = sizeof(stats);

		if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &slen))
			error(1, errno, "getsockopt xdp statistics");

		printf("xdp stats: rx[dropped=%llu inval=%llu rq_full=%llu,fq_empty=%llu] tx[inval=%llu, tq_empty=%llu]\n",
		       stats.rx_dropped, stats.rx_invalid_descs,
		       stats.rx_ring_full, stats.rx_fill_ring_empty_descs,
		       stats.tx_invalid_descs, stats.tx_ring_empty_descs);
	}

	/* PF_XDP uses atexit to always clean its (persistent) state at exit */
	if (cfg_sk_domain != PF_XDP) {
		if (close(fd))
			error(1, errno, "close");
	}

	/* stats are only valid on client: request-receive pair */
	if (cfg_client) {
		if (print_stats(num_trans))
			return 1;
	}

	return ret;
}
