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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool cfg_is_ack;
static bool cfg_is_client;
static int cfg_ifindex;
static struct in_addr cfg_ip_dst;
static struct in_addr cfg_ip_src;
static char cfg_mac_dst[ETH_HLEN];
static char cfg_mac_src[ETH_HLEN];
const int cfg_num_runs = 10;
const int cfg_payload_len = 10;		/* must be even */
static int cfg_pkt_len;
static int cfg_proto = IPPROTO_TCP;
const int cfg_tcp_dst = 0x2222;
const int cfg_tcp_src = 0x1111;
const int cfg_timeout_us = 1000 * 1000;

static char packet[ETH_DATA_LEN];

static unsigned long gettimeofday_us(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (1000UL * 1000 * tv.tv_sec) + tv.tv_usec;
}

static uint16_t calc_csum(unsigned long sum, const uint16_t *data,
			  int num_words)
{
	int i;

	for (i = 0; i < num_words; i++)
		sum += data[i];

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t calc_tcp_csum(struct iphdr *iph, struct tcphdr *tcph)
{
	unsigned long sum = 0, tcplen;

	tcplen = ntohs(iph->tot_len) - sizeof(*iph);
	if (tcplen & 1)
		error(1, 0, "odd length: csum needs padding");

	sum += iph->daddr;
	sum += iph->saddr;
	sum += htons(iph->protocol);
	sum += htons(tcplen);

	return calc_csum(sum, (void *) tcph, tcplen >> 1);
}

static void build_pkt(void)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int off = 0, tslen;

	eth = (void *) packet;
	memcpy(&eth->h_dest, cfg_mac_dst, ETH_ALEN);
	memcpy(&eth->h_source, cfg_mac_src, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	off += sizeof(*eth);

	if (cfg_proto == IPPROTO_UDP)
		tslen = sizeof(*udph);
	else
		tslen = sizeof(*tcph);
	cfg_pkt_len = sizeof(*eth) + sizeof(*iph) + tslen + cfg_payload_len;

	iph = (void *) packet + off;
	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = 2;
	iph->id = 666;
	iph->frag_off = htons(IP_DF);
	iph->tot_len = htons((uint16_t) (sizeof(*iph) + tslen + cfg_payload_len));
	iph->saddr = cfg_ip_src.s_addr;
	iph->daddr = cfg_ip_dst.s_addr;
	iph->protocol = cfg_proto;
	iph->check = calc_csum(0, (void *) iph, sizeof(*iph) >> 1);
	off += sizeof(*iph);

	if (cfg_proto == IPPROTO_UDP) {
		udph = (void *) packet + off;
		udph->dest = htons(cfg_tcp_dst);
		udph->source = htons(cfg_tcp_src);
		udph->len = htons(tslen + cfg_payload_len);
		udph->check = 0;
		off += sizeof(*udph);
	} else {
		tcph = (void *) packet + off;
		tcph->dest = htons(cfg_tcp_dst);
		tcph->source = htons(cfg_tcp_src);
		tcph->seq = htonl(1);
		tcph->ack_seq = htonl(1);
		tcph->doff = 5;
		if (cfg_is_ack)
			tcph->ack = 1;
		tcph->psh = 1;
		tcph->window = htons(16000);
		tcph->check = calc_tcp_csum(iph, tcph);
		off += sizeof(*tcph);
	}
}

static void do_recv(int fd)
{
	char rdata[ETH_DATA_LEN] = {0};
	int ret;

	ret = read(fd, rdata, sizeof(rdata));
	if (ret == -1)
		error(1, errno, "read");
	/* TODO: understand why returned packet exceeds cfg_pkt_len */
	if (ret < cfg_pkt_len)
		error(1, 0, "read: %uB != %uB\n", ret, cfg_pkt_len);
}

static void do_send(int fd)
{
	int ret;

	ret = send(fd, packet, cfg_pkt_len, MSG_DONTWAIT);
	if (ret == -1)
		error(1, errno, "write");
	if (ret != cfg_pkt_len)
		error(1, 0, "write: %uB != %uB\n", ret, cfg_pkt_len);
}

static void do_server(int fd)
{
	unsigned long t1, t2 = 0;
	int i;

	for (i = 0; i < cfg_num_runs; i++) {
		do_recv(fd);
		t1 = t2;
		t2 = gettimeofday_us();
		do_send(fd);

		if (t1)
			fprintf(stderr, "%d. RTT: %lu usec\n", i, t2 - t1);
	}
	do_send(fd);
}

static void do_client(int fd)
{
	unsigned long t1, t2;
	int i;

	for (i = 0; i < cfg_num_runs; i++) {
		t1 = gettimeofday_us();
		do_send(fd);
		do_recv(fd);
		t2 = gettimeofday_us();

		fprintf(stderr, "%d. RTT: %lu usec\n", i, t2 - t1);
	}
}

static void set_filter(int fd)
{
	const int ip_prot_off = sizeof(struct ethhdr) + 
				__builtin_offsetof(struct iphdr, protocol);
	const int tcp_dst_off = sizeof(struct ethhdr) + sizeof(struct iphdr) +
				__builtin_offsetof(struct tcphdr, dest);

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD  + BPF_B   + BPF_ABS, ip_prot_off),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, cfg_proto, 0, 3),
		BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, tcp_dst_off),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, cfg_tcp_dst, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, 0xFFFF),
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct sock_fprog prog;

	prog.filter = filter;
	prog.len = sizeof(filter) / sizeof(struct sock_filter);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)))
		error(1, errno, "setsockopt filter mark");
}

static void read_mac(const char *mac_str, char *mac_bin)
{
	if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &mac_bin[0], &mac_bin[1], &mac_bin[2],
		   &mac_bin[3], &mac_bin[4], &mac_bin[5]) != 6)
		error(1, 0, "bad mac: %s\n", optarg);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "acd:D:i:s:S:u")) != -1) {
		switch (c) {
		case 'a':
			cfg_is_ack = true;
			break;
		case 'c':
			cfg_is_client = true;
			break;
		case 'd':
			if (inet_pton(PF_INET, optarg, &cfg_ip_dst) != 1)
				error(1, 0, "bad src ip: %s\n", optarg);
			break;
		case 'D':
			read_mac(optarg, cfg_mac_dst);
			break;
		case 'i':
			cfg_ifindex = if_nametoindex(optarg);
			if (!cfg_ifindex)
				error(1, errno, "if_nametoindex");
			break;
		case 's':
			if (inet_pton(PF_INET, optarg, &cfg_ip_src) != 1)
				error(1, 0, "bad src ip: %s\n", optarg);
			break;
		case 'S':
			read_mac(optarg, cfg_mac_src);
			break;
		case 'u':
			cfg_proto = IPPROTO_UDP;
			break;
		default:
			error(1, 0, "unknown option %c", c);
		}
	}

	if (!cfg_ifindex) {
		cfg_ifindex = if_nametoindex("eth0");
		if (!cfg_ifindex)
			error(1, errno, "if_nametoindex");
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_ll addr = {0};
	int fd;

	parse_opts(argc, argv);
	fprintf(stderr, "mode: %s\n", cfg_is_client ? "client" : "server");

	fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (fd == -1)
		error(1, errno, "socket");

	set_filter(fd);

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_ifindex = cfg_ifindex;
	if (bind(fd, (void*) &addr, sizeof(addr)))
		error(1, errno, "bind");

	build_pkt();

	if (cfg_is_client)
		do_client(fd);
	else
		do_server(fd);

	if (close(fd))
		error(1, errno, "close");

	return 0;
}

