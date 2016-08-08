/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 * Author: willemb@google.com (Willem de Bruijn)
 *
 * Netlink support library
 * Geared at NETLINK_NETFILTER
 *
 * Read netfilter nflog output, for instance:
 *   `iptables -A OUTPUT -j NFLOG --nflog-group=10`
 *
 * To timestamp every packet, use the xt_time match:
 *   `iptables -A OUTPUT \
 *             -m time --timestart 00:00 --timestop 23:59 \
 *             -j NFLOG --nflog-group=10`
 * or even
 *   `iptables -A OUTPUT -m time -j NFLOG --nflog-group=10`
 *
 * TODO(willemb): optimize by using mmapped ring.
 */

#define _GNU_SOURCE
#define _BSD_SOURCE       /* for be64toh */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnflog.h"

static int config_group = 10;       /* nfnetlink group to follow */
static int config_debug_lvl = 0;

#define IOVLEN 8
#define PKTLEN (1 << 11)

static void __nflog_sendcmd(int fd, uint8_t cmd, void *msg, int msglen,
                            uint16_t family, uint16_t group_id)
{
  static int seq_id;
  char buf[1024] __attribute__((aligned));
  struct nlmsghdr *nh;
  struct nfgenmsg *ng;
  struct nfattr *nfa;
  int ret;

  memset(buf, 0, sizeof(buf));

  nh = (void *) buf;
  ng = (void *) buf + sizeof(*nh);

  nh->nlmsg_len = NLMSG_LENGTH(sizeof(*ng));
  nh->nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
  nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nh->nlmsg_pid = 0;
  nh->nlmsg_seq = ++seq_id;

  ng->nfgen_family = family;
  ng->version = NFNETLINK_V0;
  ng->res_id = htons(group_id);

  nfa = (void *) buf + NLMSG_ALIGN(nh->nlmsg_len);
  nfa->nfa_type = cmd;
  nfa->nfa_len = NFA_LENGTH(msglen);

  memcpy(NFA_DATA(nfa), msg, msglen);

  nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + NFA_ALIGN(nfa->nfa_len);

  if (send(fd, buf, nh->nlmsg_len, 0) != nh->nlmsg_len)
    error(1, errno, "sendcmd");

  /* TODO(willemb): handle EINTR */
  ret = recv(fd, buf, sizeof(buf), 0);
  if (ret == -1)
    error(1, errno, "recv ctrl: sock error");
  if (ret < NLMSG_OK(nh, ret))
    error(1, 0, "recv ctrl: insufficient length");
  if (nh->nlmsg_type != NLMSG_ERROR)
    error(1, 0, "recv ctrl: unexpected type");
  ret = *(int *) NLMSG_DATA(nh);
  if (ret)
    error(1, ret, "recv ctrl: nflog error");
}

static void nflog_sendcmd(int fd, uint8_t cmd, uint16_t family,
                          uint16_t group_id)
{
  struct nfulnl_msg_config_cmd msg;

  memset(&msg, 0, sizeof(msg));
  msg.command = cmd;
  __nflog_sendcmd(fd, NFULA_CFG_CMD, &msg, sizeof(msg), family, group_id);
}

static void nflog_sendcmd_mode(int fd, uint16_t family, uint16_t group_id,
                               uint8_t mode, uint32_t value)
{
  struct nfulnl_msg_config_mode msg;

  memset(&msg, 0, sizeof(msg));
  msg.copy_mode = mode;
  msg.copy_range = htonl(value);
  __nflog_sendcmd(fd, NFULA_CFG_MODE, &msg, sizeof(msg), family, group_id);
}

static void nflog_attach_inet(int fd, unsigned int snaplen)
{
  nflog_sendcmd(fd, NFULNL_CFG_CMD_PF_UNBIND, AF_INET, 0);
  /* TODO: recv ack */
  nflog_sendcmd(fd, NFULNL_CFG_CMD_PF_BIND, AF_INET, 0);
  /* TODO: recv ack */
  nflog_sendcmd(fd, NFULNL_CFG_CMD_BIND, AF_UNSPEC, config_group);
  /* TODO: recv ack */

  nflog_sendcmd_mode(fd, AF_UNSPEC, config_group, NFULNL_COPY_PACKET, snaplen);
  /* TODO: recv ack */
}

int nflog_init(unsigned int snaplen)
{
  struct sockaddr_nl nladdr;
  int fd, val;

  if (snaplen > PKTLEN)
    error(1, 0, "snaplen exceeds pktlen: can cause drops");

  fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
  if (fd == -1)
    error(1, errno, "socket");

  val = 1 << 21;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)))
    error(1, errno, "setsockopt SO_RCVBUF");

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_groups = 1 << config_group;

  if (bind(fd, (void *) &nladdr, sizeof(nladdr)))
    error(1, errno, "bind");

  nflog_attach_inet(fd, snaplen);
  return fd;
}

void nflog_exit(int fd)
{
  if (close(fd))
    error(1, errno, "close");
}

void nflog_parse(const void *data, unsigned int len, log_fn fn)
{
  const struct nlmsghdr *nh;

  for (nh = (void *) data; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
    const struct nfulnl_msg_packet_timestamp *nf_ts;
    const struct nfgenmsg *ng;
    const struct nfattr *attr;
    uint64_t ts_sec = 0, ts_usec = 0;
    const char *pkt;
    int plen = 0;
    int alen;

    if (nh->nlmsg_type == NLMSG_ERROR)
      error(1, 0, "netlink error");
    if (nh->nlmsg_type == NLMSG_NOOP)
      error(1, 0, "netlink noop");
    if (nh->nlmsg_len < sizeof(*nh) || len < nh->nlmsg_len) {
      fprintf(stderr, "message truncated\n");
      continue;
    }

    ng = NLMSG_DATA(nh);
    if (config_debug_lvl)
      fprintf(stderr, "P family=%s version=%d group=%d len=%d type=%hu\n",
              ng->nfgen_family == AF_INET ? "INET" : "other",
              ng->version,
              ntohs(ng->res_id),
              nh->nlmsg_len,
              nh->nlmsg_type);

    attr = NFM_NFA(ng);
    alen = nh->nlmsg_len - NLMSG_LENGTH(NLMSG_ALIGN(sizeof(*ng)));
    while (NFA_OK(attr, alen)) {
      switch (NFA_TYPE(attr)) {
        case NFULA_PAYLOAD:
          pkt = NFA_DATA(attr);
          plen = NFA_PAYLOAD(attr);
          break;
        case NFULA_TIMESTAMP:
          nf_ts = NFA_DATA(attr);
          ts_sec = be64toh(nf_ts->sec);
          ts_usec = be64toh(nf_ts->usec);
          break;
        case NFULA_GID:
        case NFULA_PACKET_HDR:
        case NFULA_PREFIX:
        case NFULA_IFINDEX_OUTDEV:
        case NFULA_UID:
        default:
          if (config_debug_lvl)
            fprintf(stderr, "  attr @%lu other type=%d\n",
                    ((unsigned long) attr) - (unsigned long) ng,
                    NFA_TYPE(attr));
      }
      attr = NFA_NEXT(attr, alen);
    }

    if (nh->nlmsg_type == NLMSG_DONE)
      break;

    fn(pkt, plen, ts_sec, ts_usec);
  }
}

int nflog_read(int fd, log_fn fn)
{
  static char data[IOVLEN][PKTLEN];
  struct mmsghdr msgs[IOVLEN];
  struct iovec iovecs[IOVLEN];
  int i, len;

  memset(msgs, 0, sizeof(msgs));
  for (i = 0; i < IOVLEN; i++) {
    iovecs[i].iov_base = data[i];
    iovecs[i].iov_len = PKTLEN;
    msgs[i].msg_hdr.msg_iov = &iovecs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  len = recvmmsg(fd, msgs, IOVLEN, MSG_DONTWAIT, NULL);
  if (len == -1) {
    if (errno == EAGAIN || errno == EINTR)
      return 0;
    if (errno == ENOBUFS) {
      static int report_overflow;
      if (!report_overflow) {
        report_overflow = 1;
        fprintf(stderr, "nflog: socket overflow detected. some packets will be lost (only warning once).\n");
      }
      return 0;
    }
    error(1, errno, "recvmsg");
  }

  if (config_debug_lvl > 1)
    fprintf(stderr, "recvmmsg len=%u\n", len);

  for (i = 0; i < len; i++)
    nflog_parse(data[i], msgs[i].msg_len, fn);

  return 1;
}

static int nflog_wait(int fd)
{
    struct pollfd pollfd[2];
    int len;

    do {
      memset(&pollfd, 0, sizeof(pollfd));

      pollfd[0].events = POLLIN;
      pollfd[0].fd = 0;

      pollfd[1].events = POLLIN;
      pollfd[1].fd = fd;

      len = poll(pollfd, 2, 50);
      if (len == -1) {
        if (errno == EINTR)
          continue;
        error(1, errno, "poll");
      }
      if (len && pollfd[0].revents)
        return 0;
    } while (!len);

    return 1;
}

void nflog_loop(int fd, log_fn fn)
{
  while (nflog_wait(fd)) {
    while (nflog_read(fd, fn)) {}
  }
}

void nflog_all(log_fn fn, unsigned int snaplen)
{
  int fd;

  fd = nflog_init(snaplen);
  nflog_loop(fd, fn);
  nflog_exit(fd);
}

