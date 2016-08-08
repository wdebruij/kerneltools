/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Packet socket support library
 *
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "libpsock.h"

static void
psock_init_ring(struct psock *ps)
{
  struct tpacket_req tp;
  int frames_per_block;

  if (ps->frame_size & (TPACKET_ALIGNMENT - 1))
    error(1, 0, "illegal frame size");

  tp.tp_frame_size = ps->frame_size;
  tp.tp_frame_nr = ps->frame_count;

  frames_per_block = getpagesize() / ps->frame_size;
  tp.tp_block_size = getpagesize();
  tp.tp_block_nr = ps->frame_count / frames_per_block;

  if (setsockopt(ps->fd, SOL_PACKET, PACKET_RX_RING, (void*) &tp, sizeof(tp)))
    error(1, errno, "setsockopt() ring");

  ps->ring = mmap(0, tp.tp_block_size * tp.tp_block_nr,
                  PROT_READ | PROT_WRITE, MAP_SHARED, ps->fd, 0);
  if (!ps->ring)
    error(1, 0, "mmap()");
}

struct sock_filter egress_filter[] = {
  { BPF_LD|BPF_B|BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PKTTYPE },
  { BPF_JMP|BPF_JEQ, 1, 0, PACKET_OUTGOING },
  { BPF_RET, 0, 0, 0x00000000 },
  { BPF_RET, 0, 0, 0x0000ffff }
};

struct sock_fprog egress_fprog = {
    .len = sizeof(egress_filter) / sizeof(egress_filter[0]),
    .filter = egress_filter,
};

void
psock_init(struct psock *ps)
{
  int val;

  ps->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (ps->fd < 0)
    error(1, errno, "socket()");

  val = TPACKET_V2;
  if (setsockopt(ps->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)))
    error(1, errno, "setsockopt() version");
  val = 1;
  if (setsockopt(ps->fd, SOL_PACKET, PACKET_TIMESTAMP, &val, sizeof(val)))
    error(1, errno, "setsockopt() tstamp");
  if (setsockopt(ps->fd, SOL_SOCKET, SO_ATTACH_FILTER,
                 &egress_fprog, sizeof(egress_fprog)))
    error(1, errno, "setsockopt() filter");

  if (ps->dev) {
    struct sockaddr_ll laddr;

    memset(&laddr, 0, sizeof(laddr));
    laddr.sll_family = AF_PACKET;
    laddr.sll_protocol = htons(ETH_P_ALL);  /* must be on ptype_all to sniff egress */
    laddr.sll_ifindex = if_nametoindex(ps->dev);
    if (!laddr.sll_ifindex)
      error(1, errno, "no such device: %s", ps->dev);
    if (bind(ps->fd, (void *) &laddr, sizeof(laddr)))
      error(1, errno, "bind device: %s (%d)", ps->dev, laddr.sll_ifindex);
  }

  psock_init_ring(ps);
}

static int
psock_wait(struct psock *ps)
{
  struct pollfd pollset[2];
  int ret;

  pollset[0].fd = 0;
  pollset[0].events = POLLIN;
  pollset[0].revents = 0;

  pollset[1].fd = ps->fd;
  pollset[1].events = POLLIN;
  pollset[1].revents = 0;

  ret = poll(pollset, 2, 100);
  if (ret < 0 && errno != EINTR && errno != EAGAIN)
    error(1, errno, "poll()");

  if (ret > 0 && pollset[0].revents)
    return 0;

  return 1;
}

int
psock_read(struct psock *ps, psock_fn fn)
{
  struct tpacket2_hdr *header;

  header = (void *) ps->ring + (ps->idx_reader * ps->frame_size);

  if (!(header->tp_status & TP_STATUS_USER))
    return 0;
  if (header->tp_status & TP_STATUS_COPY)
    error(1, 0, "detected incomplete packed");
  if (header->tp_status & TP_STATUS_LOSING) {
    static int report_overflow;
    if (!report_overflow) {
      report_overflow = 1;
      fprintf(stderr, "psock: socket overflow detected. some packets will be lost (only warning once).\n");
    }
  }

  fn(header, ((void *) header) + header->tp_mac);

  header->tp_status = TP_STATUS_KERNEL;
  ps->idx_reader = (ps->idx_reader + 1) & (ps->frame_count - 1);
  return 1;
}

void
psock_loop(struct psock *ps, psock_fn fn)
{
  while (psock_wait(ps)) {
    while (psock_read(ps, fn)) {}
  }
}

void
psock_exit(struct psock *ps)
{
  if (munmap(ps->ring, ps->frame_count * ps->frame_size))
    error(1, errno, "munmap");

  if (close(ps->fd))
    error(1, errno, "close");
}

void
psock_all(int frame_count, int frame_size, const char *dev, psock_fn fn)
{
  struct psock ps;

  memset(&ps, 0, sizeof(ps));

  ps.frame_count = frame_count;
  ps.frame_size = frame_size;
  if (dev)
    ps.dev = dev;

  psock_init(&ps);
  psock_loop(&ps, fn);
  psock_exit(&ps);
}

