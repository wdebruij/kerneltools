/* allocate and make device mem available with nv_p2pdma.ko */

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
#include <syslog.h>
#include <syslog.h>
#include <syslog.h>
#include <syslog.h>
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

const char cfg_procfs_prefix[] = "/proc/driver/nvdma";
const char *cfg_pci_bdf;

static CUcontext ctx;
static cudaIpcMemHandle_t mem_handle;

static void cuda_error(const char *fn, CUresult err) {
  const char *name = "[unknown]", *explanation = "[unknown]";

  if (cuGetErrorName(err, &name))
    fprintf(stderr, "Error: error getting error name\n");
  if (cuGetErrorString(err, &explanation))
    fprintf(stderr, "Error: error getting error string\n");

  fprintf(stderr, "CUDA Error in func %s: %d %s (%s)", fn, err, name,
          explanation);
}

/* register a gpumem region with the nvdma driver that exposes it as p2pdma */
static int nvdma_register(int id, unsigned long uvaddr, unsigned long len) {
  static char filepath[PATH_MAX];
  static char buf[60];
  int fd, slen, ret;

  sprintf(filepath, "%s/%s/new", cfg_procfs_prefix, cfg_pci_bdf);
  fd = open(filepath, O_WRONLY);
  if (fd == -1) {
	  fprintf(stderr, "Error opening %s\n", filepath);
	  return -EBADF;
  }

  slen = sprintf(buf, "0x%lx,%lu", uvaddr, len);
  ret = write(fd, buf, slen);
  if (ret != slen) {
    fprintf(stderr, "write [%s](%dB): %d\n", buf, slen, ret == -1 ? errno : 0);
    goto err_close;
  }

  if (close(fd)) {
    fprintf(stderr, "close: %d\n", errno);
    return -EIO;
  }

  syslog(LOG_INFO, "Registered region %u of %luB\n", id, len);
  return 0;

err_close:
  close(fd);
  return -EIO;
}

static int nvdma_export_file(void) {
  const char *path = "/tmp/nvdma";
  int fd, ret;

  fd = open(path, O_CREAT | O_WRONLY, 0600);
  if (fd == -1) {
    fprintf(stderr, "ERR open");
    return 1;
  }
  ret = write(fd, &mem_handle, sizeof(mem_handle));
  if (ret != sizeof(mem_handle)) {
    fprintf(stderr, "ERR write %d %d", ret, errno);
    return 1;
  }
  if (close(fd)) {
    fprintf(stderr, "ERR close");
    return 1;
  }

  fprintf(stderr, "Export to path %s\n", path);
  return 0;
}

static int nvdma_export(CUdeviceptr p) {
  cudaError_t err;

  err = cudaIpcGetMemHandle(&mem_handle, (void *)p);
  if (err) {
    fprintf(stderr, "cudaIpcGetMemHandle: %s", cudaGetErrorString(err));
    return 1;
  }

  fprintf(stderr, "Exported region of %luB (0x%p)\n", sizeof(mem_handle),
          (void *)p);

  nvdma_export_file();

  return 0;
}

static int do_alloc(size_t size) {
  static unsigned int id;
  CUdeviceptr p;
  CUresult err;

  if (size < 1 << 20) {
    fprintf(stderr, "Too small region. I've forgotten how to count that low\n");
    return -EINVAL;
  }
  /* unlikely, id overflow */
  if (id == UINT_MAX) {
    fprintf(stderr, "out of region ids");
    return -ENOBUFS;
  }

  err = cuMemAlloc(&p, size);
  if (err) {
    cuda_error("cuMemAlloc", err);
    return -EFAULT;
  }

  err = cuMemsetD32(p, 0, size / 4);
  if (err) {
    cuda_error("cuMemSet", err);
    return -EFAULT;
  }

  if (nvdma_register(id, p, size)) return -EFAULT;

  if (nvdma_export(p)) return -ENXIO;

  syslog(LOG_INFO, "Up\n");
  return id++;
}

static void check_pci_bdf(const char *str) {
  char filepath[60];
  unsigned int b, d, f;

  if (sscanf(str, "%x:%x.%x", &b, &d, &f) != 3) {
    fprintf(stderr, "unable to parse pci bdf\n");
    exit(1);
  }

  sprintf(filepath, "/sys/bus/pci/devices/%s", str);
  if (!access(filepath, F_OK)) {
    fprintf(stderr, "unable to find pci device %s\n", filepath);
    exit(1);
  }
}

static void do_fork(void) {
  pid_t pid;

  pid = fork();
  if (pid == -1) error(1, errno, "fork");

  if (pid) exit(0);
}

static void do_daemonize(void) {
  if (setsid() == (pid_t)-1) error(1, errno, "setsid");

  openlog("nvdmad", LOG_CONS, LOG_DAEMON);

  if ((chdir("/tmp")) < 0) error(1, errno, "chdir");

  close(0);
  close(1);
  close(2);
}

int main(int argc, char **argv) {
  CUresult err;
  int fd;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pci bdf>\n", argv[0]);
    return 1;
  }

  cfg_pci_bdf = argv[1];

  do_fork();

  err = cuInit(0);
  if (err) {
    cuda_error("cuInit", err);
    return 1;
  }

  err = cuDeviceGet(&fd, 0);
  if (err) {
    cuda_error("cuDeviceGet", err);
    return 1;
  }

  err = cuCtxCreate(&ctx, 0, fd);
  if (err) {
    cuda_error("cuCtxCreate", err);
    return 1;
  }

  /* Register initial bounce buffer */
  if (do_alloc(1UL << 24)) return 1;

  fprintf(stderr, "Up. Device p2pdma pool ready. Running indefinitely.\n");

  /* Daemonization moves logging to syslog.
   * For now, just avoid daemonization. You probably want to run as background
   * job */
  if (1)
    fprintf(stderr,
            "Skipping daemonize. Consider moving to background process.\n");
  else
    do_daemonize();

  /* When this process goes down, all cudaMalloc regions are reclaimed.
   * We do not have a solution for that aside from kernel BUG().
   * So just.. don't die.
   */
  while (1) {
    sleep(1);
  }

#if 0
  err = cuMemFree(p);
  if (err) cuda_error("cuMemFree", err);

  err = cuCtxDestroy(ctx);
  if (err) cuda_error("cuCtxDestroy", err);
#endif

  return 0;
}
