
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef IP_MAX_MTU
#define IP_MAX_MTU 0xFFFFU
#endif

static int cfg_mtu = 1500;

static void tap_set_flags(int fd, short flags, const char *devname)
{
	struct ifreq ifr;
	int ret, len;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	len = strlen(devname);
	if (len >= IFNAMSIZ)
		error(1, 0, "device name too long");

	strcpy(ifr.ifr_name, devname);

	ret = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if  (ret == -1)
		error(1, errno, "ioctl tunsetiff");
}

static void tap_set_offload(int fd)
{
	unsigned long flags;
	int ret;

	flags = TUN_F_CSUM | TUN_F_UFO;

	ret = ioctl(fd, TUNSETOFFLOAD, flags);
	if (ret == -1)
		error(1, errno, "ioctl set offload");
}

static int tap_open(char *devname)
{
	const char tun_ctrl_dev[] = "/dev/net/tun";
	int fd;

	fd = open(tun_ctrl_dev, O_RDWR);
	if (fd == -1)
		error(1, errno, "open tun ctrl");

	tap_set_flags(fd, IFF_TAP | IFF_VNET_HDR | IFF_NO_PI, devname);
	tap_set_offload(fd);

	printf("opened tap dev %s fd %d\n", devname, fd);
	return fd;
}

static uint16_t calc_sum(unsigned long sum, void *_data, int num_u16)
{
	uint16_t *data = _data;
	int i;

	for (i = 0; i < num_u16; i++)
		sum += data[i];

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return sum;
}

static void send_udp(int fd, int payload_len)
{
	char payload[IP_MAX_MTU - sizeof(struct iphdr) - sizeof(struct udphdr)];
	struct virtio_net_hdr vh;
	struct iovec iov[5];
	struct udphdr udph;
	struct ethhdr eth;
	struct iphdr iph;
	int i, len, ret;
	bool do_ufo;

	if (payload_len > sizeof(payload))
		error(1, 0, "payload_len exceeds max");

	do_ufo = sizeof(iph) + sizeof(udph) + payload_len > cfg_mtu;

	memset(&vh, 0, sizeof(vh));
	if (do_ufo) {
		vh.gso_type = VIRTIO_NET_HDR_GSO_UDP;
		vh.gso_size = cfg_mtu - sizeof(iph);

		vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		vh.csum_start = sizeof(eth) + sizeof(iph);
		vh.csum_offset = __builtin_offsetof(struct udphdr, check);
	}

	memset(&eth, 0, sizeof(eth));
	eth.h_proto = htons(ETH_P_IP);
	eth.h_source[1] = 1;
	eth.h_source[5] = 1;
	eth.h_dest[1] = 1;
	eth.h_dest[5] = 2;

	memset(&iph, 0, sizeof(iph));
	iph.version = 4;
	iph.ihl = 5;
	iph.tot_len = htons(sizeof(iph) + sizeof(udph) + payload_len);
	iph.ttl = 8;
	iph.protocol = IPPROTO_UDP;
	iph.saddr = htonl((192 << 24) + (168 << 16) + (14 << 8) + 1);
	iph.daddr = htonl((192 << 24) + (168 << 16) + (14 << 8) + 2);
	iph.check = ~calc_sum(0, &iph, iph.ihl << 1);

	memset(&udph, 0, sizeof(udph));
	udph.source = htons(9);
	udph.dest = htons(9);
	udph.len = htons(sizeof(udph) + payload_len);

	/* pseudohdr csum only */
	udph.check = calc_sum(htons(IPPROTO_UDP) + udph.len, &iph.saddr, 4);

	memset(payload, 'a', payload_len);

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &vh;
	iov[0].iov_len = sizeof(vh);
	iov[1].iov_base = &eth;
	iov[1].iov_len = sizeof(eth);
	iov[2].iov_base = &iph;
	iov[2].iov_len = sizeof(iph);
	iov[3].iov_base = &udph;
	iov[3].iov_len = sizeof(udph);
	iov[4].iov_base = payload;
	iov[4].iov_len = payload_len;

	ret = writev(fd, iov, sizeof(iov) / sizeof(iov[0]));
	if (ret == -1)
		error(1, errno, "writev (errno %d)", errno);

	len = 0;
	for (i = 0; i < (sizeof(iov) / sizeof(iov[0])); i++)
		len += iov[i].iov_len;

	if (ret != len)
		error(1, 0, "writev: %uB != %uB\n", ret, len);

	printf("sent %uB\n", ret);
}

static void file_set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val == -1)
		error(1, errno, "fctnl get");
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		error(1, errno, "fcntl set");
}

static void recv_all(int fd, int timeout_ms)
{
	char payload[IP_MAX_MTU - sizeof(struct iphdr) - sizeof(struct udphdr)];
	struct virtio_net_hdr vh;
	struct iovec iov[5];
	struct udphdr udph;
	struct ethhdr eth;
	struct iphdr iph;
	int ret;

	file_set_nonblock(fd);

	/* yes, this could be handled more gracefully .. */
	usleep(timeout_ms * 1000);

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &vh;
	iov[0].iov_len = sizeof(vh);
	iov[1].iov_base = &eth;
	iov[1].iov_len = sizeof(eth);
	iov[2].iov_base = &iph;
	iov[2].iov_len = sizeof(iph);
	iov[3].iov_base = &udph;
	iov[3].iov_len = sizeof(udph);
	iov[4].iov_base = payload;
	iov[4].iov_len = sizeof(payload);

	while (true) {
		ret = readv(fd, iov, sizeof(iov) / sizeof(iov[0]));
		if (ret == -1 && errno == EAGAIN)
			break;
		if (ret == -1)
			error(1, errno, "recv");

		printf("rx: %uB \n", ret);

		if (ret < sizeof(vh))
			continue;
		printf("  vh[flags:0x%x type:%u]\n", vh.flags, vh.gso_type);

		if (ret < sizeof(vh) + sizeof(eth))
			continue;
		printf("  eth[dst:%x:%x:%x:%x:%x:%x src:%x:%x:%x:%x:%x:%x proto:0x%x]\n",
			eth.h_dest[0], eth.h_dest[1], eth.h_dest[2],
			eth.h_dest[3], eth.h_dest[4], eth.h_dest[5],
			eth.h_source[0], eth.h_source[1], eth.h_source[2],
			eth.h_source[3], eth.h_source[4], eth.h_source[5],
			ntohs(eth.h_proto));

		if (ret < sizeof(vh) + sizeof(eth) + sizeof(iph))
			continue;
		if (ntohs(eth.h_proto) != ETH_P_IP)
			continue;
		printf("  ip[proto:%u len:%u]\n", iph.protocol, ntohs(iph.tot_len));
		if (iph.frag_off) {
			uint16_t frag_off = ntohs(iph.frag_off);
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif
			printf("  frag[field:0x%x off:%u df:%c mf:%c]\n",
					frag_off,
					(frag_off & IP_OFFSET) << 3,
					frag_off & IP_DF ? 'y' : 'n',
					frag_off & IP_MF ? 'y' : 'n');
			if (iph.frag_off & IP_OFFSET)
				continue;
		}
		if (iph.protocol != IPPROTO_UDP)
			continue;

		if (ret < sizeof(vh) + sizeof(eth) + sizeof(iph) + sizeof(udph))
			continue;
		printf("  udp[src:%u dst:%u len:%u check:0x%x]\n",
		       ntohs(udph.source), ntohs(udph.dest),
		       ntohs(udph.len), udph.check);
	}
}

int main(int argc, char **argv)
{
	int fdt, fdr;

	if (argc != 3)
		error(1, 0, "Usage: %s <tap_tx> <tap_rx>\n", argv[0]);

	fdt = tap_open(argv[1]);
	fdr = tap_open(argv[2]);

	send_udp(fdt, 1);
	recv_all(fdr, 100);

	send_udp(fdt, 4000);
	recv_all(fdr, 100);

	if (close(fdr))
		error(1, errno, "close tun r");
	if (close(fdt))
		error(1, errno, "close tun t");

	return 0;
}

