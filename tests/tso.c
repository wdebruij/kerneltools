// SPDX-License-Identifier: GPL-2.0

/* Test TCP Segmentation Offload (TSO) engines by creating specific
 * TSO packets, to test all kinds of edge cases.
 *
 * TSO requires checksum offload. To build custom packets in userspace
 * that configure netdev offloads, use PF_PACKET with PACKET_VNET_HDR.
 *
 * Variants supported:
 * - IPv6/TCP (only)
 * - with/without checksum offload
 * - with/without segmentation offload
 * - with/without transport mode encryption header (UDP/PSP)
 * - configurable MSS
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <errno.h>
#include <error.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static char *cfg_ifname = "eth0";
static char *cfg_macaddr_dst;
static char *cfg_macaddr_src;
static int cfg_mss = 1000;
static int cfg_mark;
static int cfg_num_pkt = 1;
static char cfg_payload_char = 'a';
static int cfg_payload_len = 3001;
static uint16_t cfg_port_dst = 34000;
static uint16_t cfg_port_src = 33000;
static int cfg_random_seed;
static bool cfg_tso;
static bool cfg_use_psp;

static struct ethhdr eth;
static struct sockaddr_in6 cfg_daddr6 = {.sin6_family = AF_INET6};
static struct sockaddr_in6 cfg_saddr6 = {.sin6_family = AF_INET6};

struct psphdr {
  uint8_t nh;
  uint8_t extlen;
  uint8_t cryptoff;
  uint8_t flags;
  uint32_t spi;
  uint64_t iv; /* merged iv/sequence number */
};

static uint32_t checksum_nofold(char *data, size_t len, uint32_t sum) {
  uint16_t *words = (uint16_t *)data;
  int i;

  for (i = 0; i < len / 2; i++)
    sum += words[i];

  if (len & 1) sum += ((unsigned char *)data)[len - 1];

  return sum;
}

/* match behavior of __tcp_v4_send_check */
static uint16_t pseudo_csum(void *th, uint16_t proto, size_t len) {
  uint32_t sum;
  int alen;

  alen = 32;

  sum = checksum_nofold(th - alen, alen, 0);
  sum += htons(proto);
  sum += htons(len);

  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

static void build_packet_eth(void)
{
  int ret;

  ret = sscanf(cfg_macaddr_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &eth.h_source[0], &eth.h_source[1], &eth.h_source[2],
               &eth.h_source[3], &eth.h_source[4], &eth.h_source[5]);
  if (ret != 6)
    error(1, 0, "cannot parse src mac addr %s", cfg_macaddr_src);

  ret = sscanf(cfg_macaddr_dst, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &eth.h_dest[0], &eth.h_dest[1], &eth.h_dest[2],
               &eth.h_dest[3], &eth.h_dest[4], &eth.h_dest[5]);
  if (ret != 6)
    error(1, 0, "cannot parse dst mac addr %s", cfg_macaddr_dst);

  eth.h_proto = htons(ETH_P_IPV6);
}

static void *build_packet_ipv6(void *_ip6h) {
  struct ipv6hdr *ip6h = _ip6h;

  memset(ip6h, 0, sizeof(*ip6h));

  ip6h->version = 6;

  if (cfg_use_psp)
    ip6h->payload_len = htons(sizeof(struct udphdr) + sizeof(struct psphdr) +
                              sizeof(struct tcphdr) + cfg_payload_len);
  else
    ip6h->payload_len = htons(sizeof(struct tcphdr) + cfg_payload_len);

  if (cfg_use_psp)
    ip6h->nexthdr = IPPROTO_UDP;
  else
    ip6h->nexthdr = IPPROTO_TCP;
  ip6h->hop_limit = 8;
  ip6h->saddr = cfg_saddr6.sin6_addr;
  ip6h->daddr = cfg_daddr6.sin6_addr;

  return ip6h + 1;
}

static void *build_packet_udp(void *_uh) {
  struct udphdr *uh = _uh;

  memset(uh, 0, sizeof(*uh));

  uh->source = htons(cfg_port_src);
  uh->dest = htons(1000);  // hard-coded for psp
  uh->check = 0;
  uh->len = htons(cfg_payload_len + sizeof(*uh) +
                  sizeof(struct tcphdr) +
                  sizeof(struct psphdr));

  return uh + 1;
}

static void *build_packet_psp(void *_ph) {
  struct psphdr *ph = _ph;

  memset(ph, 0, sizeof(*ph));

  ph->nh = IPPROTO_TCP;  // next hdr length
  ph->extlen = sizeof(ph->iv) / 8;
  ph->cryptoff = 0;
  ph->flags = 0x1;
  ph->spi = htonl(1);  // hard-coded to be 1 in IMC
  ph->iv = 0;

  return ph + 1;
}

static void *build_packet_tcp(void *_th) {
  struct tcphdr *th = _th;

  memset(th, 0, sizeof(*th));

  th->source = htons(cfg_port_src);
  th->dest = htons(cfg_port_dst);
  th->doff = 5;
  th->psh = 1;
  th->check = pseudo_csum(th, IPPROTO_TCP, sizeof(*th) + cfg_payload_len);

  return th + 1;
}

static int build_packet(char *buf, int max_len) {
  int *buf32 = (void *) buf;
  char *off;
  int i, pkt_len;

  build_packet_eth();

  if (cfg_random_seed) {
    for (i = 0; i < (max_len / sizeof(int)); i++)
      buf32[i] = rand();
  } else {
    memset(buf, cfg_payload_char, max_len);
  }

  off = build_packet_ipv6(buf);
  if (cfg_use_psp) {
    off = build_packet_udp(off);
    off = build_packet_psp(off);
  }
  off = build_packet_tcp(off);

  pkt_len = sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + cfg_payload_len;

  if (cfg_use_psp)
    pkt_len += sizeof(struct udphdr) + sizeof(struct psphdr);

  return pkt_len;
}

static void __transmit_packet(int fd, struct msghdr *msg, int len)
{
  int ret;

  ret = sendmsg(fd, msg, 0);
  if (ret == -1)
    error(1, errno, "send pf_packet");
  if (ret != len)
    error(1, 0, "send pf_packet: %dB != %dB\n", ret, len);

  if (close(fd))
    error(1, errno, "close pf_packet");

  /* reset for msg reuse */
  msg->msg_flags = 0;
}

static void transmit_packets(const char *pkt, int len)
{
  struct virtio_net_hdr vh = {0};
  struct sockaddr_ll addr = {0};
  struct msghdr msg = {0};
  struct iovec iov[3];
  int fd, i, val = 1;

  fd = socket(PF_PACKET, SOCK_RAW, 0);
  if (fd == -1)
    error(1, errno, "socket pf_packet");
  if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &val, sizeof(val)))
    error(1, errno, "setsockopt vnet");
  if (cfg_mark &&
      setsockopt(fd, SOL_SOCKET, SO_MARK, &cfg_mark, sizeof(cfg_mark)))
    error(1, errno, "setsockopt mark");

  addr.sll_family    = AF_PACKET;
  addr.sll_protocol  = htons(ETH_P_IPV6);
  addr.sll_halen    = ETH_ALEN;
  addr.sll_ifindex  = if_nametoindex(cfg_ifname);
  if (!addr.sll_ifindex)
    error(1, errno, "if_nametoindex %s", cfg_ifname);

  /* causes skb->ip_summed to be set to CHECKSUM_UNNECESSARY */
  vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
  vh.hdr_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr);
  if (cfg_use_psp)
    vh.hdr_len += sizeof(struct udphdr) + sizeof(struct psphdr);
  vh.csum_start = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
  if (cfg_use_psp)
    vh.csum_start += sizeof(struct udphdr) + sizeof(struct psphdr);
  vh.csum_offset = __builtin_offsetof(struct tcphdr, check);

  if (cfg_tso) {
    vh.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
    vh.gso_size = cfg_mss;
  }

  iov[0].iov_base = &vh;
  iov[0].iov_len = sizeof(vh);
  iov[1].iov_base = &eth;
  iov[1].iov_len = sizeof(eth);
  iov[2].iov_base = (char *) pkt;
  iov[2].iov_len = len;

  msg.msg_iov = iov;
  msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);

  len = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;

  for (i = 0; i < cfg_num_pkt; i++)
    __transmit_packet(fd, &msg, len);
}

static void parse_args(int argc, char *const argv[]) {
  const char *daddr = NULL, *saddr = NULL;
  int c;

  while ((c = getopt(argc, argv, "d:D:i:l:m:M:n:pr:s:S:T")) != -1) {
    switch (c) {
      case 'd':
        cfg_macaddr_dst = optarg;
        break;
      case 'D':
        daddr = optarg;
        break;
      case 'i':
        cfg_ifname = optarg;
        break;
      case 'l':
        cfg_payload_len = strtol(optarg, NULL, 0);
        break;
      case 'm':
        cfg_mss = strtol(optarg, NULL, 0);
        break;
      case 'M':
        cfg_mark = strtol(optarg, NULL, 0);
        break;
      case 'n':
        cfg_num_pkt = strtol(optarg, NULL, 0);
        break;
      case 'p':
        cfg_use_psp = true;
        break;
      case 'r':
        cfg_random_seed = strtol(optarg, NULL, 0);
         break;
      case 's':
        cfg_macaddr_src = optarg;
        break;
      case 'S':
        saddr = optarg;
        break;
      case 'T':
        cfg_tso = true;
        break;
      default:
        error(1, 0, "unknown arg %c", c);
    }
  }

  if (!daddr || !saddr) error(1, 0, "Must pass -D <daddr> and -S <saddr>");

  if (cfg_tso && (cfg_payload_len <= cfg_mss))
    error(1, 0, "tso: payload len must exceed mss");
  else if ((!cfg_tso) && cfg_payload_len > cfg_mss)
    error(1, 0, "no tso: payload len may not exceed mss");

  if (cfg_payload_len > IP_MAXPACKET - sizeof(struct ipv6hdr) -
                            sizeof(struct udphdr) - sizeof(struct psphdr) -
                            sizeof(struct tcphdr))
    error(1, 0, "Payload length exceeds max");

  if (inet_pton(AF_INET6, daddr, &cfg_daddr6.sin6_addr) != 1)
    error(1, errno, "Cannot parse ipv6 -D");
  if (inet_pton(AF_INET6, saddr, &cfg_saddr6.sin6_addr) != 1)
    error(1, errno, "Cannot parse ipv6 -S");

  cfg_saddr6.sin6_port = htons(cfg_port_src);
  cfg_daddr6.sin6_port = htons(cfg_port_dst);

}

int main(int argc, char **argv)
{
  static char buf[IP_MAXPACKET];
  int len;

  parse_args(argc, argv);

  srand(cfg_random_seed);

  len = build_packet(buf, sizeof(buf));

  transmit_packets(buf, len);

  return 0;
}

