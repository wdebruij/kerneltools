/* Inject packets with PACKET_TX_RING and PACKET_VNET_HDR */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if 0
/* requires libcap-dev */
#include <sys/capability.h>
#else
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
#endif

#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS	20
#endif

static bool cfg_enable_ring = true;
static bool cfg_enable_vnet = false;
static bool cfg_enable_csum = true;	/* only used if cfg_enable_vnet */
static bool cfg_enable_gso = true;	/* only used if cfg_enable_vnet */
static char *cfg_ifname = "eth0";
static int cfg_ifindex;
static int cfg_num_frames = 4;
static unsigned int cfg_override_len = UINT_MAX;
static unsigned int cfg_payload_len = 500;
static bool cfg_qdisc_bypass = false;

static struct tpacket_req req;
static struct in_addr ip_saddr, ip_daddr;

/* must configure real daddr (should really infer or pass on cmdline) */
const char cfg_mac_src[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
const char cfg_mac_dst[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

static int socket_open(void)
{
	int fd, val;

	fd = socket(PF_PACKET, SOCK_RAW, 0 /* disable reading */);
	if (fd == -1)
		error(1, errno, "socket");

	val = TPACKET_V2;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)))
		error(1, errno, "setsockopt version");

	if (cfg_qdisc_bypass) {
		val = 1;
		if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS,
			       &val, sizeof(val)))
			error(1, errno, "setsockopt qdisc bypass");
	}

	if (cfg_enable_vnet) {
		val = 1;
		if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR,
			       &val, sizeof(val)))
			error(1, errno, "setsockopt vnet_hdr");
	}

	return fd;
}

static char * ring_open(int fd)
{
	char *ring;
	unsigned int frame_sz;

	frame_sz = cfg_payload_len + 100 /* overestimate */;
	frame_sz = 1 << (32 - __builtin_clz(frame_sz));
	if (frame_sz < getpagesize())
		frame_sz = getpagesize();

	fprintf(stderr, "frame size: %u\n", frame_sz);

	req.tp_frame_size = frame_sz;
	req.tp_frame_nr   = cfg_num_frames;
	req.tp_block_size = req.tp_frame_size;
	req.tp_block_nr   = cfg_num_frames;

	if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING,
		       (void*) &req, sizeof(req)))
		error(1, errno, "setsockopt ring");

	ring = mmap(0, req.tp_block_size * req.tp_block_nr,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED)
		error(1, errno, "mmap");

	return ring;
}

/* warning: does not handle odd length */
static unsigned long add_csum_hword(const uint16_t *start, int num_u16)
{
	unsigned long sum = 0;
	int i;

	for (i = 0; i < num_u16; i++)
		sum += start[i];

	return sum;
}

static uint16_t add_csum_hword_fold(const uint16_t *start, int num_u16,
				    unsigned long sum)
{
	sum += add_csum_hword(start, num_u16);

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

static uint16_t build_ip_csum(const uint16_t *start, int num_u16,
			      unsigned long sum)
{
	return ~add_csum_hword_fold(start, num_u16, sum);
}

static uint16_t get_tcp_v4_csum(const struct iphdr *iph,
				const struct tcphdr *tcph,
				int length)
{
	unsigned long pseudo_sum = 0;
	uint16_t proto = htons(IPPROTO_TCP);
	uint16_t ulen = htons(length);

	pseudo_sum = add_csum_hword_fold((void *) &iph->saddr, 4, 0);
	pseudo_sum = add_csum_hword_fold(&proto, 1, pseudo_sum);
	pseudo_sum = add_csum_hword_fold(&ulen, 1, pseudo_sum);

	if (cfg_enable_vnet)
		return pseudo_sum;
	else
		return build_ip_csum((void *) tcph, length >> 1, pseudo_sum);
}

static int frame_fill(void *buffer, unsigned int payload_len)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int off = 0;

	if (cfg_enable_vnet) {
		struct virtio_net_hdr *vnet;

		vnet = buffer;

		if (cfg_enable_csum) {
			vnet->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			vnet->csum_start = ETH_HLEN + sizeof(*iph);
			vnet->csum_offset = __builtin_offsetof(struct tcphdr, check);
		}

		if (cfg_enable_gso) {
			vnet->hdr_len = ETH_HLEN + sizeof(*iph) + sizeof(*tcph);
			vnet->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			vnet->gso_size = ETH_DATA_LEN - sizeof(struct iphdr) -
							sizeof(struct tcphdr);
		} else {
			vnet->gso_type = VIRTIO_NET_HDR_GSO_NONE;
		}

		off += sizeof(*vnet); 
	}

	eth = buffer + off;
	memcpy(&eth->h_source, cfg_mac_src, ETH_ALEN);
	memcpy(&eth->h_dest, cfg_mac_dst, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	off += ETH_HLEN;

	iph = buffer + off;
	iph->ttl	= 8;
	iph->ihl	= 5;
	iph->version	= 4;
	iph->saddr	= ip_saddr.s_addr;
	iph->daddr	= ip_daddr.s_addr;
	iph->protocol	= IPPROTO_TCP;
	iph->tot_len	= htons(sizeof(*iph) + sizeof(*tcph) + payload_len);
	iph->check	= build_ip_csum((const void *) iph, 10 /* hwords */, 0); 
	off += sizeof(*iph);

	tcph = buffer + off;
	tcph->dest	= htons(9);
	tcph->source	= htons(9);
	tcph->doff	= sizeof(*tcph) >> 2;
	off += sizeof(*tcph);

	memset(buffer + off, 'a', payload_len);

	tcph->check	= get_tcp_v4_csum(iph, tcph,
					  (sizeof(*tcph) + payload_len));
	return off + payload_len;
}

static void ring_write(void *slot)
{
	struct tpacket2_hdr *header = slot;
	int len;

	if (header->tp_status != TP_STATUS_AVAILABLE)
		error(1, 0, "write: slot not available");

	header->tp_mac = TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
	memset(slot + header->tp_mac, 0, req.tp_frame_size - header->tp_mac);

	len = frame_fill(slot + header->tp_mac, cfg_payload_len);
	if (cfg_override_len < len)
		len = cfg_override_len;

	header->tp_len = len;
	header->tp_status = TP_STATUS_SEND_REQUEST;
}

static void socket_write(int fd)
{
	static char buf[ETH_HLEN + (1 << 16)];
	int len, ret;

	memset(buf, 0, sizeof(buf));
	len = frame_fill(buf, cfg_payload_len);

	if (cfg_override_len < len)
		len = cfg_override_len;

	ret = send(fd, buf, len, 0);
	if (ret == -1)
		error(1, errno, "send");
	if (ret < len)
		error(1, 0, "send: %uB < %uB\n", ret, len);
}

static void socket_bind(int fd)
{
	struct sockaddr_ll addr = { 0 };

	addr.sll_family =	AF_PACKET;
	addr.sll_ifindex =	cfg_ifindex;
	addr.sll_protocol =	htons(ETH_P_IP);
	addr.sll_halen =	ETH_ALEN;

	if (bind(fd, (void *) &addr, sizeof(addr)))
		error(1, errno, "bind");
}

static void ring_wake_kernel(int fd)
{
	int ret;

	ret = send(fd, NULL, 0, 0);
	if (ret < 0)
		error(1, errno, "send");
	if (!ret)
		error(1, 0, "send: no data");

	fprintf(stderr, "send: %uB\n", ret);
}

static void ring_close(char *ring)
{
	if (munmap(ring, req.tp_block_size * req.tp_block_nr))
		error(1, errno, "munmap");
}

static void do_run_ring(int fd, char *ring)
{
	int i;

	for (i = 0; i < cfg_num_frames; i++)
		ring_write(ring + (i * req.tp_frame_size));

	ring_wake_kernel(fd);
}

static void do_run(int fd)
{
	int i;

	for (i = 0; i < cfg_num_frames; i++)
		socket_write(fd);
}

static void drop_capability(uint32_t capability)
{
	struct __user_cap_header_struct hdr = {};
	struct __user_cap_data_struct data = {};

	hdr.pid = getpid();
	hdr.version = _LINUX_CAPABILITY_VERSION;

	if (capget(&hdr, &data) == -1)
		error(1, errno, "capget");
	fprintf(stderr, "cap.1: eff=0x%x perm=0x%x\n",
			data.effective, data.permitted);

	data.effective &= ~CAP_TO_MASK(capability);
	data.permitted &= ~CAP_TO_MASK(capability);
	data.inheritable = 0;

	if (capset(&hdr, &data) == -1)
		error(1, errno, "capset");

	if (capget(&hdr, &data) == -1)
		error(1, errno, "capget");
	fprintf(stderr, "cap.2: eff=0x%x perm=0x%x\n",
			data.effective, data.permitted);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "cCd:Gi:l:L:n:Nqs:v")) != -1)
	{
		switch (c) {
		case 'c':
			drop_capability(CAP_SYS_RAWIO);
			break;
		case 'C':
			cfg_enable_csum = false;
			break;
		case 'd':
			if (!inet_aton(optarg, &ip_daddr))
				error(1, 0, "bad ipv4 destination address");
			break;
		case 'G':
			cfg_enable_gso = false;
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'l':
			cfg_payload_len = strtoul(optarg, NULL, 0);
			break;
		case 'L':
			cfg_override_len = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			cfg_num_frames = strtoul(optarg, NULL, 0);
			break;
		case 'N':
			cfg_enable_ring = false;
			break;
		case 'q':
			cfg_qdisc_bypass = true;
			break;
		case 's':
			if (!inet_aton(optarg, &ip_saddr))
				error(1, 0, "bad ipv4 destination address");
			break;
		case 'v':
			cfg_enable_vnet = true;
			break;
		default:
			error(1, 0, "unknown option %c", c);
		}
	}

	if (!ip_saddr.s_addr || !ip_daddr.s_addr)
		error(1, 0, "must specify ipv4 source and destination");

	cfg_ifindex = if_nametoindex(cfg_ifname);
	if (!cfg_ifindex)
		error(1, errno, "ifnametoindex");

	fprintf(stderr, "len:  %u\n", cfg_num_frames);
	fprintf(stderr, "num:  %u\n", cfg_payload_len);
	fprintf(stderr, "vnet: %sabled\n", cfg_enable_vnet ? "en" : "dis");
}

int main(int argc, char **argv)
{
	char *ring;
	int fd;

	parse_opts(argc, argv);

	fd = socket_open();
	socket_bind(fd);

	if (cfg_enable_ring) {
		ring = ring_open(fd);
		do_run_ring(fd, ring);
		ring_close(ring);
	} else {
		do_run(fd);
	}

	if (close(fd) == -1)
		error(1, errno, "close");

	return 0;
}
