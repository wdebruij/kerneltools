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

/*
 * A packet sniffer that combines PACKET_RX_RING and PACKET_VNET_HDR
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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

static bool cfg_enable_vnet = false;
static int cfg_num_frames = 1024;
static int cfg_runtime_sec = 1;

static struct tpacket_req req;

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static int socket_open(void)
{
	int fd, val;

	fd = socket(PF_PACKET, SOCK_RAW, 0 /* disable until ring is ready */);
	if (fd == -1)
		error(1, errno, "socket");

	val = TPACKET_V2;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)))
		error(1, errno, "setsockopt version");

	if (cfg_enable_vnet) {
		val = 1;
		if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR,
			       &val, sizeof(val)))
			error(1, errno, "setsockopt vnet_hdr");
	}

	return fd;
}

static void socket_bind(int fd)
{
	struct sockaddr_ll addr = {};

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	if (bind(fd, (void *) &addr, sizeof(addr)) == -1)
		error(1, errno, "packetsock bind");
}

static char * ring_open(int fd)
{
	char *ring;
	
	req.tp_frame_size = 256;
	req.tp_frame_nr   = cfg_num_frames;
	req.tp_block_size = getpagesize();
	req.tp_block_nr   = (req.tp_frame_size * req.tp_frame_nr) /
			    req.tp_block_size;

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
		       (void*) &req, sizeof(req)))
		error(1, errno, "setsockopt ring");

	ring = mmap(0, req.tp_block_size * req.tp_block_nr,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED)
		error(1, errno, "mmap");

	return ring;
}

/* portability warning: ignoring virtio endiannes */
static void parse_vnet(struct virtio_net_hdr *vnet)
{
	uint16_t gso_type;
	char *type;

	gso_type = vnet->gso_type & ~VIRTIO_NET_HDR_GSO_ECN;
	switch (gso_type) {
	case VIRTIO_NET_HDR_GSO_NONE:
		type = "none";
		break;
	case VIRTIO_NET_HDR_GSO_TCPV4:
		type = "tcpv4";
		break;
	case VIRTIO_NET_HDR_GSO_TCPV6:
		type = "tcpv6";
		break;
	case VIRTIO_NET_HDR_GSO_UDP:
		type = "udp";
		break;
	default:
		type = "unknown";
	}

	fprintf(stderr, "vnet: gso_type=%s gso_size=%u hlen=%u ecn=%s\n",
			type, vnet->gso_size, vnet->hdr_len,
			(vnet->gso_type & VIRTIO_NET_HDR_GSO_ECN) ? "on " : "off");

	if (vnet->flags == VIRTIO_NET_HDR_F_NEEDS_CSUM)
		fprintf(stderr, "csum: start=%u off=%u\n",
				vnet->csum_start, vnet->csum_offset);

}

static void parse_ipv4(struct iphdr *iph)
{
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

	if (!inet_ntop(AF_INET, &iph->saddr, saddr, sizeof(saddr)))
		error(1, errno, "inet_ntop saddr");
	if (!inet_ntop(AF_INET, &iph->daddr, daddr, sizeof(daddr)))
		error(1, errno, "inet_ntop daddr");

	fprintf(stderr, "ip: src=%s dst=%s proto=%u len=%u\n",
			saddr, daddr, iph->protocol, ntohs(iph->tot_len));
}

/* portability warning: assumes ethernet */
static void __ring_read(struct tpacket2_hdr *hdr, void *data)
{
	struct timeval tv;
	uint16_t eth_proto;
	struct ethhdr *eth = (void *) data;

	gettimeofday(&tv, NULL);
	fprintf(stderr, "\npkt: %lu.%lu len=%u\n",
			tv.tv_sec, tv.tv_usec, hdr->tp_len);

	if (cfg_enable_vnet)
		parse_vnet(data - sizeof(struct virtio_net_hdr));

	eth_proto = htons(eth->h_proto);
	fprintf(stderr, "eth: proto=0x%x\n", eth_proto);
	if (eth_proto == ETH_P_IP)				
		parse_ipv4(data + ETH_HLEN);
}

static void ring_read(void *ring, int index)
{
	struct tpacket2_hdr *header = ring + (index * req.tp_frame_size);

	if (!(header->tp_status & TP_STATUS_USER))
		error(1, 0, "ring: no data (0x%x)", header->tp_status);


	__ring_read(header, ((void *) header) + header->tp_mac);
	header->tp_status = TP_STATUS_KERNEL;
}

static void ring_close(char *ring)
{
	if (munmap(ring, req.tp_block_size * req.tp_block_nr))
		error(1, errno, "munmap");
}

static bool ring_poll(int fd)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 100);
	if (ret == -1)
		error(1, errno, "poll");
	if (ret == 0)
		return false;
	if (pfd.revents != POLLIN)
		error(1, 0, "unexpected event (0x%x)", pfd.revents);

	return true;
}

static void do_run(int fd, char *ring)
{
	int64_t tstop, index = 0;

	tstop = gettimeofday_ms() + (cfg_runtime_sec * 1000);
	
	while (gettimeofday_ms() < tstop) {
		if (ring_poll(fd)) {
			ring_read(ring, index % cfg_num_frames);
			index++;
		}
	}

	fprintf(stderr, "total: %lu packets\n", index);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "v")) != -1)
	{
		switch (c) {
		case 'v':
			cfg_enable_vnet = true;
			break;
		default:
			error(1, 0, "unknown option %c", c);
		}
	}
}

int main(int argc, char **argv)
{
	char *ring;
	int fd;

	parse_opts(argc, argv);

	fprintf(stderr, "vnet: %sabled\n", cfg_enable_vnet ? "en" : "dis");

	fd = socket_open();
	socket_bind(fd);
	ring = ring_open(fd);

	do_run(fd, ring);

	ring_close(ring);
	if (close(fd) == -1)
		error(1, errno, "close");

	return 0;
}
