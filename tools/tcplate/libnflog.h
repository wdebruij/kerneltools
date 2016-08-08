/*
 * Copyright 2014 Google Inc.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Netfilter LOG support library
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

#ifndef _LIBNFLOG_H_
#define _LIBNFLOG_H_

#include <stdint.h>

/* can be called with len 0 */
typedef void (*log_fn)(const void *pkt, unsigned int len,
                       uint64_t ts_sec, uint64_t ts_usec);

void nflog_all(log_fn fn, unsigned int snaplen);

int  nflog_init(unsigned int snaplen);
int  nflog_read(int fd, log_fn fn);
void nflog_loop(int fd, log_fn fn);
void nflog_exit(int fd);

#endif // _LIBNFLOG_H_

