/*
 * Copyright 2014 Google Inc.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Packet socket support library
 *
 * Only reads outgoing packets
 *
 * License (GPLv2):
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. * See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
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

