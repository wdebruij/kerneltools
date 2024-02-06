// SPDX-License-Identifier: GPL-2.0

/* XSK basic regression test
 *
 * Exercise AF_XDP (XSK) sockets in all modes
 * - skb copy
 * - drv copy
 * - drv zerocopy
 *
 *
 * Build:
 *   clang -O2 -Wall -target bpf -I ${LIBBPF}/src -g -c xsk_hw_bpf.c -o xsk_hw_bpf.o
 *   bpftool gen skeleton xsk_hw_bpf.o > xsk_hw_bpf.skel.h
 *   gcc -static -I ${XDPTOOLS}/headers -O2 -Wall -g --o xsk_hw xsk_hw.c -\
 *       L ${XDPTOOLS}/lib/libbpf/src -L ${XDPTOOLS}/lib/libxdp/src \
 *       -lxdp -lbpf -lelf -lz -lzstd -lc -lm
 *
 * Run:
 *
 * server: ./xsk_hw -i $DEV -D $CLIENT_IPV6 -S $SERVER_IPV6 -m $LOCAL_MAC -M $GW_MAC -h $ARGS
 * client: ./xsk_hw -i $DEV -D $SERVER_IPV6 -S $CLIENT_IPV6 -m $LOCAL_MAC -M $GW_MAC $ARGS
 *
 * Args:
 *
 * - ``: no args: minimal connectivity sanity test using PF_PACKET
 *
 * - `-T -s -c`: test transmit, skb copy mode
 * - `-T -d -c`: test transmit, driver copy mode
 * - `-T -d -z`: test transmit, driver zerocopy mode
 *
 * - `-R -s -c`: receive, skb copy mode
 * - `-R -d -c`: receive, driver copy mode
 * - `-R -d -z`: receive, driver zerocopy mode
 */

#include <arpa/inet.h>
#include <error.h>
#include <linux/errqueue.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/udp.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xdp/xsk.h>
#include "xsk_hw_bpf.skel.h"

static struct in6_addr cfg_daddr, cfg_saddr;
static bool cfg_host_run;
static char *cfg_ifname = "eth0";
static int cfg_ifindex;
static char *cfg_mac_dst, *cfg_mac_src;
static int cfg_num_rxq;
static uint16_t cfg_port = __constant_htons(8000);
static const char cfg_payload[] = "aaaaaaaa";
static int cfg_send_queue_id = 0;
static __u32 cfg_xdp_flags = XDP_FLAGS_REPLACE;
static __u16 cfg_xdp_bind_flags;
static bool cfg_xdp_rx;
static bool cfg_xdp_tx;
static bool cfg_xdp_tx_force_attach;

static char pkt[ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(cfg_payload)];

#define UMEM_NUM 8192
#define UMEM_QLEN (UMEM_NUM / 2)
#define UMEM_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_FRAME_SIZE * UMEM_NUM)

struct xsk {
	void *umem_area;
	struct xsk_umem *umem;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_socket *socket;
	__u32 tx_head;
};

static struct xsk_hw_bpf *bpf_obj;
static struct xsk *xsks;

static int pfpacket_fd;
static int udp_fd;

static uint32_t checksum_nofold(void *data, size_t len, uint32_t sum)
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
	struct udphdr *uh;
	uint32_t sum;

	/* init mac header */
	eth = (void *)&pkt;
	if (sscanf(cfg_mac_dst, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &eth->h_dest[0], &eth->h_dest[1], &eth->h_dest[2],
		   &eth->h_dest[3], &eth->h_dest[4], &eth->h_dest[5]) != 6)
		error(1, 0, "sscanf mac dst ('-M') \n");
	if (sscanf(cfg_mac_src, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &eth->h_source[0], &eth->h_source[1], &eth->h_source[2],
		   &eth->h_source[3], &eth->h_source[4], &eth->h_source[5]) != 6)
		error(1, 0, "sscanf mac src ('-m')\n");
	eth->h_proto = htons(ETH_P_IPV6);

	/* init ipv6 header */
	ip6h = (void *)(eth + 1);

	ip6h->daddr = cfg_daddr;
	ip6h->saddr = cfg_saddr;
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->payload_len = htons(sizeof(*uh) + sizeof(cfg_payload));
	ip6h->hop_limit = 64;

	/* init udp header */
	uh = (void *)(ip6h + 1);
	uh->source = cfg_port;
	uh->dest = cfg_port;
	uh->len = htons(sizeof(*uh) + sizeof(cfg_payload));
	uh->check = 0;

	/* init payload */
	memcpy(uh + 1, cfg_payload, sizeof(cfg_payload));

	/* udp checksum */
	sum = checksum_nofold(uh, sizeof(*uh) + sizeof(cfg_payload), 0);
	sum = checksum_nofold(&ip6h->daddr, sizeof(ip6h->daddr), sum);
	sum = checksum_nofold(&ip6h->saddr, sizeof(ip6h->saddr), sum);
	sum += htons(IPPROTO_UDP);
	sum += ip6h->payload_len;

	uh->check = checksum_fold(NULL, 0, sum);
}

static void verify_pkt(void *data, size_t len)
{
	void *data_end = data + len;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	struct udphdr *uh;

	eth = data;
	data = eth + 1;
	if (data > data_end)
		goto bad;
	if (eth->h_proto != htons(ETH_P_IPV6))
		goto bad;

	ip6h = data;
	data = ip6h + 1;
	if (data > data_end)
		goto bad;
	if (ip6h->nexthdr != IPPROTO_UDP)
		goto bad;

	uh = data;
	data = uh + 1;
	if (data > data_end)
		goto bad;
	if (uh->dest != cfg_port)
		goto bad;

	if (data_end - data != sizeof(cfg_payload))
		goto bad;
	if (memcmp(data, cfg_payload, sizeof(cfg_payload)))
		goto bad;

	return;
bad:
	error(1, 0, "bad packet content");
}

static void udp_bind(void)
{
	struct sockaddr_in6 ip6addr = {
		.sin6_family = AF_INET6,
		.sin6_port = cfg_port,
		.sin6_addr = cfg_saddr,
	};

	if (bind(udp_fd, (void *)&ip6addr, sizeof(ip6addr)) == -1)
		error(1, 0, "udp bind");
}

static void pfpacket_setfilter_ipproto(void)
{
	int off_proto, off_port;

	off_proto = ETH_HLEN + offsetof(struct ipv6hdr, nexthdr);
	off_port = ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest);

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PACKET_HOST, 0, 5),
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, off_proto),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 3),
		BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, off_port),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ntohs(cfg_port), 0, 1),
		BPF_STMT(BPF_RET + BPF_K, 0xFFFF),
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct sock_fprog prog = {};

	prog.filter = filter;
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	if (setsockopt(pfpacket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		error(1, errno, "setsockopt filter");
}

static void pfpacket_bind(void)
{
	struct sockaddr_ll laddr = {
		.sll_family = AF_PACKET,
		.sll_protocol = cfg_xdp_rx ? 0 : htons(ETH_P_IPV6),
		.sll_ifindex = cfg_ifindex,
	};

	if (bind(pfpacket_fd, (void *)&laddr, sizeof(laddr)) == -1)
		error(1, 0, "pfpacket bind");
}

static int open_xsk(struct xsk *xsk, __u32 queue_id)
{
	const int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	const struct xsk_socket_config socket_config = {
		.rx_size = UMEM_QLEN,
		.tx_size = UMEM_QLEN,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = cfg_xdp_flags,
		.bind_flags = cfg_xdp_bind_flags,
	};
	const struct xsk_umem_config umem_config = {
		.fill_size = UMEM_QLEN,
		.comp_size = UMEM_QLEN,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	};
	__u32 idx;
	__u64 addr;
	int ret;
	int i;

	xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (xsk->umem_area == MAP_FAILED)
		return -ENOMEM;

	ret = xsk_umem__create(&xsk->umem,
			       xsk->umem_area, UMEM_SIZE,
			       &xsk->fill,
			       &xsk->comp,
			       &umem_config);
	if (ret)
		return ret;

	ret = xsk_socket__create(&xsk->socket, cfg_ifname, queue_id,
				 xsk->umem,
				 &xsk->rx,
				 &xsk->tx,
				 &socket_config);
	if (ret)
		return ret;

	/* First half of umem is for TX. This way address matches 1-to-1
	 * to the completion queue index.
	 */

	for (i = 0; i < UMEM_QLEN; i++) {
		addr = i * UMEM_FRAME_SIZE;
		memcpy(xsk_umem__get_data(xsk->umem_area, addr),
		       pkt, sizeof(pkt));
	}

	/* Second half of umem is for RX. */

	ret = xsk_ring_prod__reserve(&xsk->fill, UMEM_QLEN, &idx);
	for (i = 0; i < UMEM_QLEN; i++) {
		addr = (UMEM_QLEN + i) * UMEM_FRAME_SIZE;
		*xsk_ring_prod__fill_addr(&xsk->fill, i) = addr;
	}
	xsk_ring_prod__submit(&xsk->fill, ret);

	return 0;
}

static void release_tx(struct xsk *xsk)
{
	__u32 idx = 0;
	unsigned int n;

	n = xsk_ring_cons__peek(&xsk->comp, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx);
	if (n)
		xsk_ring_cons__release(&xsk->comp, n);
}

static void send_xsk(void)
{
	struct xsk *xsk = &xsks[cfg_send_queue_id];
	struct xdp_desc *desc;
	__u32 idx;

	release_tx(xsk);
	if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) != 1)
		error(1, 0, "TX ring is full");

	desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
	desc->addr = (xsk->tx_head++ % UMEM_QLEN) * UMEM_FRAME_SIZE;
	desc->len = sizeof(pkt);

	xsk_ring_prod__submit(&xsk->tx, 1);
	sendto(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void refill_rx(struct xsk *xsk, __u64 addr)
{
	__u32 idx;

	if (xsk_ring_prod__reserve(&xsk->fill, 1, &idx) == 1) {
		*xsk_ring_prod__fill_addr(&xsk->fill, idx) = addr;
		xsk_ring_prod__submit(&xsk->fill, 1);
	}
}

static void recv_xsk(void)
{
	const struct xdp_desc *desc;
	struct pollfd fds[cfg_num_rxq];
	__u64 comp_addr;
	__u64 addr;
	__u32 idx;
	int ret;
	int i;

	for (i = 0; i < cfg_num_rxq; i++) {
		fds[i].fd = xsk_socket__fd(xsks[i].socket);
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	ret = poll(fds, cfg_num_rxq, 10000);
	if (ret < 0)
		error(1, -ret, "poll");
	if (ret == 0)
		error(1, 0, "recv_xsk: Timeout");

	for (i = 0; i < cfg_num_rxq; i++) {
		if (fds[i].revents == 0)
			continue;

		struct xsk *xsk = &xsks[i];

		/* Reading one packet at a time, because we expect only one
		 * packet outstanding per queue at a time due to test doing
		 * single connection request/response
		 */
		ret = xsk_ring_cons__peek(&xsk->rx, 1, &idx);
		if (ret != 1)
			continue;

		desc = xsk_ring_cons__rx_desc(&xsk->rx, idx);
		comp_addr = xsk_umem__extract_addr(desc->addr);
		addr = xsk_umem__add_offset_to_addr(desc->addr);
		verify_pkt(xsk_umem__get_data(xsk->umem_area, addr), desc->len);
		xsk_ring_cons__release(&xsk->rx, 1);
		refill_rx(xsk, comp_addr);
	}
}

static void send_pfpacket(void)
{
	int ret;

	ret = write(pfpacket_fd, pkt, sizeof(pkt));
	if (ret == -1)
		error(1, errno, "write");
	if (ret != sizeof(pkt))
		error(1, 0, "write pkt: %uB != %luB", ret, sizeof(pkt));
}

static void recv_pfpacket(void)
{
	static char recv_pkt[sizeof(pkt)];
	struct pollfd fds = {
		.fd = pfpacket_fd,
		.events = POLLIN,
	};
	int ret;

	ret = poll(&fds, 1, 10000);
	if (ret < 0)
		error(1, -ret, "poll");
	if (ret == 0)
		error(1, 0, "recv_pfpacket: Timeout");

	ret = recv(pfpacket_fd, recv_pkt, sizeof(pkt), MSG_TRUNC);
	if (ret == -1)
		error(1, errno, "recv");
	if (ret != sizeof(pkt))
		error(1, 0, "recv pkt: %uB != %luB\n", ret, sizeof(pkt));

	verify_pkt(recv_pkt, ret);
}

static void do_send(void)
{
	if (cfg_xdp_tx)
		send_xsk();
	else
		send_pfpacket();
}

static void do_recv(void)
{
	if (cfg_xdp_rx)
		recv_xsk();
	else
		recv_pfpacket();
}

static int get_num_rxq(void)
{
	struct ethtool_channels ch = {
		.cmd = ETHTOOL_GCHANNELS,
	};
	struct ifreq ifr = {
		.ifr_data = (void *)&ch,
	};
	int fd, ret;

	strcpy(ifr.ifr_name, cfg_ifname);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket");

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret < 0)
		error(1, errno, "socket");

	close(fd);

	return ch.rx_count + ch.combined_count;
}

static bool link_is_down(void)
{
	char path[PATH_MAX];
	FILE *file;
	char status;

	snprintf(path, PATH_MAX, "/sys/class/net/%s/carrier", cfg_ifname);
	file = fopen(path, "r");
	if (!file)
		error(1, errno, "%s", path);

	if (fread(&status, 1, 1, file) != 1)
		error(1, errno, "fread");

	fclose(file);

	return status == '0';
}

static void cleanup(void)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);

	if (bpf_obj) {
		opts.old_prog_fd = bpf_program__fd(bpf_obj->progs.rx);
		if (opts.old_prog_fd >= 0)
			bpf_xdp_detach(cfg_ifindex, cfg_xdp_flags, &opts);
	}
}

static void parse_opts(int argc, char **argv)
{
	char *daddr = NULL, *saddr = NULL;
	int c;

	while ((c = getopt(argc, argv, "cD:dhi:m:M:p:q:RS:sTz")) != -1) {
		switch (c) {
		case 'c':
			cfg_xdp_bind_flags |= XDP_COPY;
			break;
		case 'D':
			daddr = optarg;
			break;
		case 'd':
			cfg_xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 'h':
			cfg_host_run = true;
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'm':
			cfg_mac_src = optarg;
			break;
		case 'M':
			cfg_mac_dst = optarg;
			break;
		case 'p':
			cfg_port = htons(atoi(optarg));
			break;
		case 'q':
			cfg_send_queue_id = atoi(optarg);
			break;
		case 'R':
			cfg_xdp_rx = true;
			break;
		case 'S':
			saddr = optarg;
			break;
		case 's':
			cfg_xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'T':
			if (cfg_xdp_tx)
				cfg_xdp_tx_force_attach = true;
			cfg_xdp_tx = true;
			break;
		case 'z':
			cfg_xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		default:
			error(1, 0, "%s: parse error", argv[0]);
		}
	}

	if (!cfg_mac_src || !cfg_mac_dst || !saddr || !daddr)
		error(1, 0, "all MAC and IP addresses must be set");

	if (inet_pton(AF_INET6, daddr, &cfg_daddr) != 1)
		error(1, 0, "ipv6 parse error: dst ('-D')");
	if (inet_pton(AF_INET6, saddr, &cfg_saddr) != 1)
		error(1, 0, "ipv6 parse error: src ('-S')");

	cfg_ifindex = if_nametoindex(cfg_ifname);
	if (!cfg_ifindex)
		error(1, 0, "ifname invalid");
}

static void handle_signal(int sig)
{
	exit(1);
}

int main(int argc, char *argv[])
{
	int ret;
	int i;

	parse_opts(argc, argv);
	init_pkt();

	/* A UDP socket to silence kernel-generated ICMP unreachable
	 * without needing an iptables rule.
	 */
	udp_fd = socket(PF_INET6, SOCK_DGRAM, 0);
	if (udp_fd == -1)
		error(1, errno, "socket");

	pfpacket_fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (pfpacket_fd == -1)
		error(1, errno, "socket");

	udp_bind();

	pfpacket_setfilter_ipproto();
	pfpacket_bind();

	cfg_num_rxq = get_num_rxq();

	if (cfg_xdp_rx || cfg_xdp_tx_force_attach) {
		bpf_obj = xsk_hw_bpf__open();
		if (libbpf_get_error(bpf_obj))
			error(1, libbpf_get_error(bpf_obj), "xsk_hw_bpf__open");

		/* Not doing bpf_program__set_ifindex because it requests offload */

		ret = xsk_hw_bpf__load(bpf_obj);
		if (ret)
			error(1, -ret, "xsk_hw_bpf__load");

		bpf_obj->bss->port = cfg_port;
		bpf_obj->bss->should_rx = cfg_xdp_rx;
	}

	xsks = calloc(cfg_num_rxq, sizeof(struct xsk));
	if (!xsks)
		error(1, ENOMEM, "malloc");

	for (i = 0; i < cfg_num_rxq; i++) {
		ret = open_xsk(&xsks[i], i);
		if (ret)
			error(1, -ret, "open_xsk");
	}

	if (cfg_xdp_rx) {
		for (i = 0; i < cfg_num_rxq; i++) {
			int sock_fd = xsk_socket__fd(xsks[i].socket);
			__u32 queue_id = i;

			ret = bpf_map__update_elem(bpf_obj->maps.xsk,
						   &queue_id, sizeof(queue_id),
						   &sock_fd, sizeof(sock_fd), 0);
			if (ret)
				error(1, -ret, "bpf_map__update_elem");
		}
	}

	if (cfg_xdp_rx || cfg_xdp_tx_force_attach) {
		ret = bpf_xdp_attach(cfg_ifindex,
				     bpf_program__fd(bpf_obj->progs.rx),
				     cfg_xdp_flags, NULL);
		if (ret)
			error(1, -ret, "bpf_xdp_attach");
	}

	atexit(cleanup);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	/* XDP may need a delay for device reinitialization */
	do {
		sleep(1);
	} while (link_is_down());

	if (cfg_host_run)
		do_recv();
	else
		do_send();
}
