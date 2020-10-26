// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

/* include linux/eventpoll.h conflicts with sys/epoll.h */
#ifndef EPOLL_NSTIMEO
#define EPOLL_NSTIMEO 0x1
#endif

static uint64_t gettime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000UL * 1000 * 1000 + ts.tv_nsec;
}

static int test_timeout(int fd)
{
	const int fudge_factor = 2;	/* allow for variance */
	const int timeo_ns = 100 * 1000;
	struct epoll_event event;
	uint64_t tdiff;
	int ret;

	tdiff = gettime_ns();
	ret = epoll_wait(fd, &event, 1, timeo_ns);
	tdiff = gettime_ns() - tdiff;
	if (ret == -1)
		error(1, errno, "epoll_wait");
	if (ret)
		error(1, 0, "epoll_wait: %d", ret);

	fprintf(stderr, "waited %lu nsec\n", tdiff);

	/* return non-zero on failure */
	return !!(tdiff > (timeo_ns * fudge_factor));
}

int main(int argc, char **argv)
{
	int failed = 0;
	int fd, i;

	fd = epoll_create1(EPOLL_NSTIMEO);
	if (fd == -1)
		error(1, errno, "epoll_create");

	for (i = 0; i < 5; i++)
		failed |= test_timeout(fd);

	if (close(fd))
		error(1, errno, "close");

	return failed;
}


