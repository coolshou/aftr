/*
 * Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: bench.c 595 2010-01-16 15:36:49Z pselkirk $ */

/*
 * Benchmark for TUN interface/device
 *
 * Francis_Dupont@isc.org, November 2008
 */

#ifndef __linux__
#include <sys/types.h>
#endif
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifndef __linux__
#include <net/if.h>
#include <net/if_tun.h>
#else
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char tunname[64];
int tunfd;

u_char buf[1500];
u_int len;

u_short id;
uint32_t seq, received;
struct timespec ts, firstts, lastts;
struct timeval tv;
uint64_t acc;
u_long dmin, dmax;

int
in_cksum(u_char *p, u_int l)
{
	int sum = 0;

	while (l > 1) {
		sum += *p++ << 8;
		sum += *p++;
		l -= 2;
	}
	if (l == 1)
		sum += *p << 8;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return (0xffff & ~sum);
}

void
build(void)
{
	int cksum, cc;
	uint32_t x;

	memset(buf, 0, 1000);
	buf[0] = 0x45;
	buf[2] = 1024 >> 8;
	buf[3] = 1024 & 0xff;
	buf[4] = id >> 8;
	buf[5] = id++ & 0xff;
	buf[6] = 0x40;
	buf[8] = 64;
	buf[9] = 1;
	buf[12] = 10;
	buf[15] = 1;
	buf[16] = 192;
	buf[17] = 168;
	buf[19] = 4;
	cksum = in_cksum(buf, 20);
	buf[10] = cksum >> 8;
	buf[11] = cksum & 0xff;
	buf[20] = 8;
	buf[24] = seq >> 24;
	buf[25] = (seq >> 16) & 0xff;
	buf[26] = (seq >> 8) & 0xff;
	buf[27] = seq++ & 0xff;
	(void) clock_gettime(CLOCK_REALTIME, &ts);
	x = ts.tv_sec;
	buf[28] = x >> 24;
	buf[29] = (x >> 16) & 0xff;
	buf[30] = (x >> 8) & 0xff;
	buf[31] = x & 0xff;
	x = ts.tv_nsec;
	buf[32] = x >> 24;
	buf[33] = (x >> 16) & 0xff;
	buf[34] = (x >> 8) & 0xff;
	buf[35] = x & 0xff;
	cksum = in_cksum(buf + 20, 1024 - 20);
	buf[22] = cksum >> 8;
	buf[23] = cksum & 0xff;
	len = 1024;

	cc = write(tunfd, buf, len);
	if (cc < 0) {
		perror("write");
		exit(1);
	}
	if (cc != len) {
		fprintf(stderr, "short write (%d != %d)\n", cc, len);
		exit(1);
	}
}

void
get(void)
{
	int cc;
	uint32_t inseq, sec, nsec;
	u_long d;

	cc = read(tunfd, buf, sizeof(buf));
	(void) clock_gettime(CLOCK_REALTIME, &ts);
	if (cc < 0) {
		perror("read");
		exit(1);
	}
	if (cc == 0) {
		fprintf(stderr, "read0\n");
		exit(1);
	}
	if (cc != 1024) {
		fprintf(stderr, "read %d\n", cc);
		return;
	}
	if (buf[0] != 0x45) {
		fprintf(stderr, "byte0 %02x\n", (u_int) buf[0]);
		return;
	}
	if (buf[9] != 1) {
		fprintf(stderr, "protocol %d\n", (int) buf[9]);
		return;
	}
	if (buf[20] != 0) {
		fprintf(stderr, "type %d\n", (int) buf[20]);
		return;
	}

	received++;

	inseq = buf[24] << 24;
	inseq |= buf[25] << 16;
	inseq |= buf[26] << 8;
	inseq |= buf[27];
	sec = buf[28] << 24;
	sec |= buf[29] << 16;
	sec |= buf[30] << 8;
	sec |= buf[31];
	nsec = buf[32] << 24;
	nsec |= buf[33] << 16;
	nsec |= buf[34] << 8;
	nsec |= buf[35];

	if (nsec > ts.tv_nsec) {
		ts.tv_sec--;
		ts.tv_nsec += 1000000000;
	}
	sec = ts.tv_sec - sec;
	nsec = ts.tv_nsec - nsec;
	d = nsec + sec * 100000000;
	acc += d;
	if ((dmin == 0) || (dmin > d))
		dmin = d;
	if (d > dmax)
		dmax = d;
}

int
tun_open(void)
{
	int fd = -1;
#ifndef __linux__
	int i;

	for (i = 0; i <= 255; i++) {
		snprintf(tunname, sizeof(tunname), "/dev/tun%d", i);
		fd = open(tunname, O_RDWR);
		if ((fd >= 0) || (errno == ENOENT))
			break;
	}
	if (fd >= 0) {
		i = 0;
		ioctl(fd, TUNSLMODE, &i);
		ioctl(fd, TUNSIFHEAD, &i);
		i = IFF_POINTOPOINT;
		ioctl(fd, TUNSIFMODE, &i);
	}
#else
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
       
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}
	ioctl(fd, TUNSETNOCSUM, 1);
#endif
	return fd;
}

int
setup_start(void)
{
	int fd;

	fd = tun_open();
	if (fd <= 0) {
		perror("tun_open");
		return -1;
	}
	if (system("./start") < 0) {
		perror("system");
		(void) system("./stop");
		close(fd);
		return -1;
	}
	tunfd = fd;
	return 1;
}

void
setup_stop(void)
{
	(void) system("./stop");
	close(tunfd);
	tunfd = -1;
}

void
loop(void)
{
	fd_set set;
	int cc;

	FD_ZERO(&set);
	FD_SET(tunfd, &set);
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	cc = select(tunfd + 1, &set, NULL, NULL, &tv);
	if (cc < 0) {
		perror("select");
		if (errno != EINTR)
			exit(-1);
	}
	if (FD_ISSET(tunfd, &set))
		get();
	if (seq < 1024 * 1024)
		build();
}

int
main(int argc, char **argv)
{
	u_long m;

	if (setup_start() <= 0) {
		fprintf(stderr, "setup_start\n");
		exit(-1);
	}
	(void) clock_gettime(CLOCK_REALTIME, &firstts);
	build();
	for (; seq < 1024 * 1024;)
		loop();
	(void) clock_gettime(CLOCK_REALTIME, &lastts);
	setup_stop();
	printf("sent %u, received %u\n", 1024U * 1024U, (u_int) received);
	printf("delay min %lu max %lu mean %lu\n",
	       dmin, dmax, (u_long)(acc / (1024 * 1024)));
	if (lastts.tv_nsec < firstts.tv_nsec) {
		lastts.tv_sec--;
		lastts.tv_nsec += 1000000000;
	}
	lastts.tv_sec -= firstts.tv_sec;
	lastts.tv_nsec -= firstts.tv_nsec;
	m = lastts.tv_sec * 1000000000 + lastts.tv_nsec;
	printf("during %lu ns (%lu ns/pkt)\n", m, m / (1024 * 1024));
	return 0;
}
