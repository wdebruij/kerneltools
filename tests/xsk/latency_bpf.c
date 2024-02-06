// SPDX-License-Identifier: GPL-2.0
/* This is to avoid sending all rx traffic to AF_XDP, which includes
 * traffic that must arrive to the kernel, such as ssh packets.
 * This filter allows only RSVP packets to go into AF_XDP.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

/* Single-queue */
#define MAX_XSKS 1

__u64 xdp_rx_timestamp;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_XSKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp")
int latency_bpf(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	eth = data;
	data = eth + 1;
	if (data > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		iph = (void *)(eth + 1);
		data = iph + 1;
		if (data + sizeof(__u32) > data_end)
			return XDP_PASS;

		if (iph->protocol == IPPROTO_RSVP)
			goto redirect;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		ip6h = (void *)(eth + 1);
		data = ip6h + 1;
		if (data + sizeof(__u32) > data_end)
			return XDP_PASS;

		if (ip6h->nexthdr == IPPROTO_RSVP)
			goto redirect;
	}

	return XDP_PASS;

redirect:
	xdp_rx_timestamp = bpf_ktime_get_ns();
	//bpf_printk("redirect @%lu ms: %uB: 0x%08x",
	//	   xdp_rx_timestamp / (1000 * 1000),
	//	   data_end - data, *(uint32_t*)data);
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
