/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Packet socket support library
 *
 * Only reads outgoing packets
 */

#ifndef _LIBPSOCK_H_
#define _LIBPSOCK_H_

#include <linux/if_packet.h>

struct psock {
  int frame_size;
  int frame_count;
  const char *dev;    /* (optional) device to bind to */

  /* internal */
  int fd;
  char *ring;
  int idx_reader;
};

typedef void (*psock_fn)(struct tpacket2_hdr *tp, void *pkt);

void psock_all(int frame_count, int frame_size, const char *dev, psock_fn fn);

void psock_init(struct psock *ps);
int  psock_read(struct psock *ps, psock_fn fn);
void psock_loop(struct psock *ps, psock_fn fn);
void psock_exit(struct psock *ps);

#endif // _LIBPSOCK_H_

