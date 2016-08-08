/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Netfilter LOG support library
 *
 * Only reads outgoing packets
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

