/* Send '-n' blocks of size '-s' over a tcp stream '-I' msec apart */

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static char 	*cfg_dst_addr;
static int	cfg_ival_ms = 1000;
static int	cfg_family = PF_INET6;
static int	cfg_num_send = 4;
static uint16_t	cfg_dst_port = 8000;
static int	cfg_send_size = 4096;

static void parse_opts(int argc, char **argv) {
  int c;

  while ((c = getopt(argc, argv, "4D:I:n:p:s:")) != -1) {
    switch (c) {
      case '4':
	cfg_family = PF_INET;
	break;
      case 'D':
        cfg_dst_addr = optarg;		    
      case 'I':
	cfg_ival_ms = strtoul(optarg, NULL, 0);
        break;
      case 'n':
	cfg_num_send = strtoul(optarg, NULL, 0);
        break;
      case 'p':
	cfg_dst_port = strtoul(optarg, NULL, 0);
        break;
      case 's':
	cfg_send_size = strtoul(optarg, NULL, 0);
        break;
      default:
        error(1, 0, "unknown option %c\n", c);
    }
  }
}

int main(int argc, char **argv)
{
	static char txbuf[IP_MAXPACKET];
	struct sockaddr_in6 addr6;
	struct sockaddr_in addr4;
	struct sockaddr *addr;
	socklen_t alen;
	int fd, ret;

	parse_opts(argc, argv);

	fd = socket(cfg_family, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	memset(&addr, 0, sizeof(addr));
	if (cfg_family == PF_INET6) {
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(cfg_dst_port);
		if (inet_pton(AF_INET6, cfg_dst_addr, &(addr6.sin6_addr)) != 1)
			error(1, errno, "inet_pton dst (%s)", cfg_dst_addr);
		addr = (void *)&addr6;
		alen = sizeof(addr6);
	} else {
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(cfg_dst_port);
		if (inet_pton(AF_INET, cfg_dst_addr, &(addr4.sin_addr.s_addr)) != 1)
			error(1, errno, "inet_pton dst (%s)", cfg_dst_addr);
		addr = (void *)&addr4;
		alen = sizeof(addr4);
	}

	if (connect(fd, addr, alen))
		error(1, errno, "connect");

	memset(txbuf, 0xBB, sizeof(txbuf));

	while (cfg_num_send--) {
		ret = write(fd, txbuf, cfg_send_size);
		if (ret == -1)
			error(1, errno, "write");
		if (ret != cfg_send_size)
			error(1, 0, "write: %dB\n", ret);
		fprintf(stderr, "sent %uB\n", ret);

		usleep(cfg_ival_ms * 1000UL);
	}

	if (close(fd))
		error(1, errno, "socket");
}

