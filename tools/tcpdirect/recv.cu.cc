#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
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

static bool cfg_rxonly;
static bool cfg_recycle_devmem;
static int cfg_recv_flags = MSG_TRUNC;
static bool cfg_scan_mem;
static int cfg_type = SOCK_DGRAM;
static bool cfg_verbose;

static int SO_DEVMEM_OFFSET = 99;
static int SCM_DEVMEM_OFFSET = SO_DEVMEM_OFFSET;

#define print_verbose(...)                         \
  do {                                             \
    if (cfg_verbose) fprintf(stderr, __VA_ARGS__); \
  } while (0)

static CUcontext ctx;

static void cuda_error(const char *fn, CUresult err) {
  const char *name = "[unknown]", *explanation = "[unknown]";

  if (cuGetErrorName(err, &name))
    fprintf(stderr, "Error: error getting error name\n");
  if (cuGetErrorString(err, &explanation))
    fprintf(stderr, "Error: error getting error string\n");

  error(1, 0, "Error in func %s: %d %s (%s)", fn, err, name, explanation);
}

__global__ void overwrite(char *buf, int shard_size) {
  int tid, off, i;

  tid = threadIdx.x;
  off = tid * shard_size;

  for (i = 0; i < shard_size; i++) {
    if (buf[i] == 0xBB) buf[i] = 0xCC;
  }
}

static void cudakernel_run_overwrite(CUdeviceptr p, unsigned int size) {
  unsigned int num_thread = 512;
  unsigned int shard_size = size / num_thread;

  overwrite<<<1, num_thread>>>((char *)p, shard_size);

  cudaDeviceSynchronize();
}

static void gpumem_show(CUdeviceptr p, size_t size) {
  CUresult err;
  char *buf;
  int i;

  buf = (char *)malloc(size);
  if (!buf) error(1, 0, "malloc");

  err = cuMemcpyDtoH(buf, p, size);
  if (err) cuda_error("cuMemcpyDToH", err);

  fprintf(stderr, "[0..255]: ");
  for (i = 0; i < 256; i += 2)
    fprintf(stderr, "%02hx%02hx ", buf[i], buf[i + 1]);
  fputc('\n', stderr);

  free(buf);
}

/* allocate and pre-fill gpu memory */
static CUdeviceptr gpumem_alloc(size_t size) {
  CUdeviceptr p;
  CUresult err;

  err = cuMemAlloc(&p, size);
  if (err) cuda_error("cuMemAlloc", err);
  fprintf(stderr, "Allocated %luB at %llx\n", size, p);

  err = cuMemsetD32(p, htonl(0xAAAAAAAA), size / 4);
  if (err) cuda_error("cuMemSet", err);

  return p;
}

/* release memory */
static void gpumem_free(CUdeviceptr p, size_t size) {
  CUresult err;

  err = cuMemFree(p);
  if (err) cuda_error("cuMemFree", err);
  fprintf(stderr, "Freed at %llx\n", p);
}

static CUdeviceptr gpumem_import(void) {
  const char nvdmad_path[] = "/tmp/nvdma";
  CUipcMemHandle mem_handle;
  CUdeviceptr ptr;
  CUresult err;
  int fd, ret;

  fd = open(nvdmad_path, O_RDONLY);
  if (fd == -1) error(1, errno, "open %s", nvdmad_path);

  ret = read(fd, &mem_handle, sizeof(mem_handle));
  if (ret == -1) error(1, errno, "read %s", nvdmad_path);
  if (ret != sizeof(mem_handle)) error(1, 0, "read %s: %dB", nvdmad_path, ret);
  if (close(fd)) error(1, errno, "close %s", nvdmad_path);

  err = cuIpcOpenMemHandle(&ptr, mem_handle, cudaIpcMemLazyEnablePeerAccess);
  if (err) cuda_error("cuIpcOpenMemHandle", err);

  return ptr;
}

static void gpumem_scan(CUdeviceptr rxmem) {
  const size_t gpumem_sz = 1UL << 24; /* hardcoded in nvdma.cu.cc */
  char *rxmem_cpu;
  CUresult err;
  int start = -1, i, found = 0;

  rxmem_cpu = (char *)malloc(gpumem_sz);
  if (!rxmem_cpu)
    error(1, 0, "%s: unable to alloc %luB\n", __func__, gpumem_sz);

  err = cuMemcpyDtoH(rxmem_cpu, rxmem, gpumem_sz);
  if (err) cuda_error("cuMemcpy #2", err);

  for (i = 0; i < gpumem_sz; i++) {
    if (rxmem_cpu[i] == 0xBB) {
      if (start == -1) start = i;
    } else if (start != -1) {
      /* only print if an repeating pattern: at least 10 char */
      if (i > start + 10)
        fprintf(stderr, "scan: 0xBB range: [%d..%d)\n", start, i);
      start = -1;
      found = 1;
    }
  }

  if (!found) fprintf(stderr, "scan: not found\n");

  free(rxmem_cpu);
}

static void gpumem_unimport(CUdeviceptr ptr) {
  CUresult err;

  err = cuIpcCloseMemHandle(ptr);
  if (err) cuda_error("cuIpcCloseMemHandle", err);
}

static bool do_poll_sock_and_stdin(int fd) {
  struct pollfd pfd[2];
  int ret;

  memset(pfd, 0, sizeof(pfd));

  pfd[0].fd = 0; /* stdin */
  pfd[0].events = POLLIN;

  pfd[1].fd = fd;
  pfd[1].events = POLLIN;

  ret = poll(pfd, 2, -1);
  if (ret == -1) error(1, errno, "poll");
  if (ret == 0) error(1, errno, "poll: unexpected timeout");

  if ((pfd[0].revents & ~POLLIN) || (pfd[1].revents & ~POLLIN))
    error(1, errno, "poll: unexpected revent 0x%x 0x%x\n", pfd[0].revents,
          pfd[1].revents);

  if (pfd[0].revents & POLLIN) return false;

  return true;
}

static unsigned long do_recv_cmsg(struct msghdr *msg, unsigned long *paddr) {
  struct cmsghdr *cm;
  struct iovec *iov;
  unsigned long ret;
  int num_cm = 0;

  ret = ULONG_MAX;
  *paddr = ULONG_MAX;

  for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
    if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_DEVMEM_OFFSET) {
      fprintf(stderr, "cmsg: unknown %u.%u\n", cm->cmsg_level, cm->cmsg_type);
      continue;
    }

    num_cm++;
    iov = (struct iovec *)CMSG_DATA(cm);
    fprintf(stderr, "cmsg: off=0x%p len=%lu\n", iov->iov_base, iov->iov_len);

    /* current version returns two cmsgs:
     * - one with offset from start of region
     * - one with raw physaddr
     * to differentiate, only the first sets iov_len */
    if (iov->iov_len)
      ret = (unsigned long)iov->iov_base;
    else
      *paddr = (unsigned long)iov->iov_base;
  }

  if (!num_cm) fprintf(stderr, "no cmsg\n");
  if (ret == ULONG_MAX)
    fprintf(stderr, "cmsgs lack offset from start of region\n");
  if (*paddr == ULONG_MAX)
    fprintf(stderr, "cmsgs lack offset from start of phys\n");
  if (!num_cm || ret == ULONG_MAX || *paddr == ULONG_MAX)
    error(1, 0, "cmsg error(s)");

  return ret;
}

static int do_open(void) {
  const int cfg_port = 8000;
  struct sockaddr_in6 addr;
  int fd, val;

  fd = socket(PF_INET6, cfg_type, 0);
  if (fd == -1) fprintf(stderr, "socket\n");

  val = 1000;
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &val, sizeof(val)))
    error(1, 0, "setsockopt mark");

  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(cfg_port);
  addr.sin6_addr = in6addr_any;
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
    error(1, 0, "bind");

  print_verbose("listening on port %u\n", cfg_port);

  if (cfg_type == SOCK_STREAM) {
    int listen_fd = fd;

    if (listen(listen_fd, 1)) error(1, errno, "listen");

    fd = accept(listen_fd, NULL, NULL);
    if (fd == -1) error(1, errno, "accept");

    print_verbose("connection accepted\n");
    if (close(listen_fd)) error(1, errno, "close (listener)");
  }

  return fd;
}

static size_t do_recv(int fd, unsigned long *off, unsigned long *paddr) {
  static char rxbuf[IP_MAXPACKET];
  char controldata[100 * CMSG_SPACE(sizeof(struct iovec))];
  unsigned long _off;
  struct msghdr msg;
  struct iovec iov;
  size_t size = 0;
  int ret;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = controldata;
  msg.msg_controllen = sizeof(controldata);

  /* TCP requires a valid buffer even with MSG_TRUNC.
   * UDP must *not* have a buffer if flushing with MSG_TRUNC.
   */
  if (!(cfg_recv_flags & MSG_TRUNC) ||
      cfg_type == SOCK_STREAM) {
    iov.iov_base = rxbuf;
    iov.iov_len = sizeof(rxbuf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
  }

  while (do_poll_sock_and_stdin(fd)) {

    ret = recvmsg(fd, &msg, cfg_recv_flags);
    if (ret == -1) {
      fprintf(stderr, "recvmsg: %d\n", errno);
      break;
    }
    size += ret;
    print_verbose("recv %uB\n", ret);

    /* EOF */
    if (ret == 0 && cfg_type == SOCK_STREAM)
      break;

    /* 0B dgrams are valid, so absense of MSG_TRUNC is not a bug */
    if (msg.msg_flags & MSG_CTRUNC) {
      fprintf(stderr, "recvmsg: insufficient cmsg space\n");
      break;
    }

    /* if receiving the payload, instead of truncating, check payload pattern */
    if (!(cfg_recv_flags & MSG_TRUNC)) {
      int i, err = 0;

      for (i = 0; i < ret; i++)
        if (rxbuf[i] != 0xAA && rxbuf[i] != 0xBB && rxbuf[i] != 0xCC) err++;

      fprintf(stderr, "recv: total=%dB correct=%dB max=%ldB\n", ret, ret - err,
              msg.msg_iov->iov_len);
    }

    fprintf(stderr, "len=%d cmsglen=%lu (of %lu)\n", ret, msg.msg_controllen,
            sizeof(controldata));

    _off = do_recv_cmsg(&msg, paddr);

    if (!*off) {
	    *off = _off;
    } else {
	    /* the caller expects all data to be contiguous
	     * TODO: update the caller, and return a scatter-gather array */
	    if (_off != *off + size - ret)
		    fprintf(stderr, "WARN: recv is not contiguous: 0x%lx != 0x%lx + %lu (0x%lx)\n",
			    _off, *off, size - ret,
			    *off + size - ret);
    }

    /* reinit msg: kernel may overwrite a few fields */
    msg.msg_controllen = sizeof(controldata);
    msg.msg_flags = 0;

    if (cfg_recv_flags & MSG_PEEK) {
      ret = recvmsg(fd, &msg, MSG_TRUNC);
      if (ret == -1) {
        fprintf(stderr, "recvmsg: %d\n", errno);
        break;
      }
      print_verbose("flush %uB\n", ret);

      /* reinit msg: kernel may overwrite a few fields */
      msg.msg_controllen = sizeof(controldata);
      msg.msg_flags = 0;
    }
  }

  return size;
}

/* TODO: replace unsafe raw paddr with dma_buf */
static void do_recycle_devmem(int fd, unsigned long paddr) {
  struct iovec iov;

/* TODO: change cmsg to pass page start + page off instead */
#if 1
  fprintf(stderr, "HACK: ALIGNING paddr at page. TODO: fix\n");
  paddr &= ~4095;
#endif

  iov.iov_base = (void *)paddr;
  iov.iov_len = 0; /* currently required: PAGE_SIZE is assumed */

  if (setsockopt(fd, SOL_SOCKET, SO_DEVMEM_OFFSET, &iov, sizeof(iov))) {
    fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
    return;
  }

  printf("recycled physaddr 0x%lx\n", paddr);
}

static void do_close(int fd) {
  if (close(fd)) fprintf(stderr, "close\n");
}

static void do_main(CUdeviceptr rxmem) {
  unsigned long off = 0, paddr;
  size_t received;
  CUdeviceptr p;
  CUresult err;
  int fd;

  /* receive from network socket */
  fd = do_open();
  received = do_recv(fd, &off, &paddr);

  /* gpu-to-gpu copy out of packet buffer to in-order buffer */
  p = gpumem_alloc(received);
  gpumem_show(p, received);

  fprintf(stderr, "cuMemcpy %luB from rxmem + %luB (0x%lx)\n", received, off,
          off);
  err = cuMemcpy(p, rxmem + off, received);
  if (err) cuda_error("cuMemcpy", err);

  /* recycle packet buffer
   * TODO: should support batching of course */
  if (cfg_recycle_devmem) do_recycle_devmem(fd, paddr);
  do_close(fd);

  /* eventually release the in-order buffer */
  gpumem_show(p, received);
  gpumem_free(p, received);

  if (cfg_scan_mem) gpumem_scan(rxmem);
}

static void parse_opts(int argc, char **argv) {
  int c;

  while ((c = getopt(argc, argv, "D:prRStTv")) != -1) {
    switch (c) {
      case 'D':
        SO_DEVMEM_OFFSET = strtol(optarg, NULL, 0);
        SCM_DEVMEM_OFFSET = SO_DEVMEM_OFFSET;
        break;
      case 'p':
        cfg_recv_flags |= MSG_PEEK;
        fprintf(stderr, "peek mode on\n");
        break;
      case 'r':
        cfg_rxonly = true;
        fprintf(stderr, "rxonly mode: skipping cuda\n");
        break;
      case 'R':
        cfg_recycle_devmem = true;
        fprintf(stderr, "recycle: on\n");
	break;
      case 'S':
        cfg_scan_mem = true;
        fprintf(stderr, "scan device mem: on\n");
        break;
      case 't':
        cfg_type = SOCK_STREAM;
        fprintf(stderr, "protocol: tcp\n");
        break;
      case 'T':
        cfg_recv_flags &= ~MSG_TRUNC;
        fprintf(stderr, "msg_trunc: off\n");
        break;
      case 'v':
        cfg_verbose = true;
        fprintf(stderr, "verbose on\n");
        break;
      default:
        error(1, 0, "unknown option %c\n", c);
    }
  }

  if (cfg_type == SOCK_STREAM && cfg_recv_flags & MSG_TRUNC)
    fprintf(stderr, "Reminder: MSG_TRUNC has a different meaning with TCP\n");
}

int main(int argc, char **argv) {
  CUdeviceptr rxmem;
  CUresult err;
  int fd;

  parse_opts(argc, argv);

  err = cuInit(0);
  if (err) cuda_error("cuInit", err);

  err = cuDeviceGet(&fd, 0);
  if (err) cuda_error("cuDeviceGet", err);

  err = cuCtxCreate(&ctx, 0, fd);
  if (err) cuda_error("cuCtxCreate", err);

  rxmem = gpumem_import();

  if (cfg_rxonly) {
    unsigned long off_unused = 0, paddr_unused;

    fd = do_open();
    do_recv(fd, &off_unused, &paddr_unused);
    do_close(fd);
  } else
    do_main(rxmem);

  gpumem_unimport(rxmem);

  err = cuCtxDestroy(ctx);
  if (err) cuda_error("cuCtxDestroy", err);

  return 0;
}
