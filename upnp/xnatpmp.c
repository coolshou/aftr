/*
 * Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
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

/* pseudo-firewall stuff for extended NAT-PMP */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "xnatpmp.h"
#include "upnpglobalvars.h"

static unsigned short cnt;
static uint32_t lasttm;

int
init_redirect(void)
{
	return 0;
}

void
shutdown_redirect(void)
{
	unsigned char buf[20];

	memset(buf, 0, sizeof(buf));
	buf[0] = 8;
	buf[1] = 'X';
	/* buf[2..3] = reserved; */
	/* buf[4..7] = iaddr; */
	/* buf[8] = version; */
	buf[9] = 1;
	/* buf[10..11] = reserved; */
	/* buf[12..13] = iport; */
	/* buf[14..15] = eport; */
	/* buf[16..19] = lifetime; */
	if (send(sxfd6, buf, 20, 0) < 0)
		syslog(LOG_WARNING, "shutdown_redirect(send1): %m");
	buf[9] = 2;
	if (send(sxfd6, buf, 20, 0) < 0)
		syslog(LOG_WARNING, "shutdown_redirect(send2): %m");
}

/* from netfilter/iptcrdr.c */

static struct rdr *
add_redirect_internal(unsigned short eport, const char *iaddr,
		      unsigned short iport, int proto,
		      uint32_t life, const char *desc)
{
	struct rdr * p;
	size_t l = 1;

	if (desc)
		l += strlen(desc);
	p = malloc(sizeof(struct rdr) + l);
	if (p) {
		memset(p, 0, sizeof(struct rdr));
		p->next = rdr_list;
		strncpy(p->iaddr, iaddr, INET_ADDRSTRLEN);
		p->proto = (short)proto;
		p->iport = iport;
		p->eport = eport;
		p->lifetime = life;
		if (life)
			p->expire = (uint32_t)
				(time(NULL) - startup_time) + life;
		if (desc)
			memcpy(p->desc, desc, l);
		rdr_list = p;
	}
	return p;
}

static void
del_redirect_internal(unsigned short eport, int proto)
{
	struct rdr *p, *last;

	p = rdr_list;
	last = 0;
	while (p) {
		if (p->eport == eport && p->proto == proto) {
			if (!last)
				rdr_list = p->next;
			else
				last->next = p->next;
			free(p);
			return;
		}
		last = p;
		p = p->next;
	}
}

static struct rdr *
get_redirect_internal(unsigned short eport, int proto)
{
	struct rdr *p;
	for (p = rdr_list; p; p = p->next) {
		if (p->eport == eport && p->proto == (short)proto)
			return p;
	}
	return 0;
}

struct rdr *
add_redirect_rule2(const char *ifname, unsigned short eport,
                   const char *iaddr, unsigned short iport, int proto,
		   unsigned int life,
		   const char *desc, unsigned short *rcode)
{
	unsigned char sbuf[20], rbuf[128];
	int cc, error;
	uint32_t tm, lt;

	memset(sbuf, 0, sizeof(sbuf));
	sbuf[0] = 8;
	sbuf[1] = rcode ? 'N' : 'U';
	cnt++;
	sbuf[2] = cnt >> 8;
	sbuf[3] = cnt & 0xff;
	if (inet_pton(AF_INET, iaddr, sbuf + 4) <= 0) {
		syslog(LOG_WARNING, "add_redirect_rule2(inet_pton)");
		return 0;
	}
	/* sbuf[8] = version; */
	sbuf[9] = proto == IPPROTO_TCP ? 2 : 1;
	if (!rcode)
		sbuf[9] += 2;
	/* sbuf[10..11] = reserved; */
	sbuf[12] = iport >> 8;
	sbuf[13] = iport & 0xff;
	sbuf[14] = eport >> 8;
	sbuf[15] = eport & 0xff;
	if (life)
		tm = (uint32_t)life;
	else
		tm = 3600U;
	tm = htonl(tm);
	memcpy(sbuf + 16, &tm, 4);
	if (send(sxfd6, sbuf, 20, 0) < 0) {
		syslog(LOG_WARNING, "add_redirect_rule2(send): %m");
		return 0;
	}

	for (;;) {
		memset(rbuf, 0, sizeof(rbuf));
		cc = recv(sxfd6, rbuf, 128, MSG_PEEK);
		if (cc < 0) {
			syslog(LOG_WARNING, "add_redirect_rule2(recv): %m");
			return 0;
		}
		sbuf[9] += 128;
		if ((cc == 24) && (memcmp(sbuf, rbuf, 10) == 0))
			break;
		ProcessXNATPMP();
	}
	(void)recv(sxfd6, rbuf, 24, 0);
	cc -= 8;
	memmove(rbuf, rbuf + 8, cc);
	error = (rbuf[2] << 8) | rbuf[3];
	if (error != 0) {
		syslog(LOG_WARNING, "add_redirect_rule2(rcode): %d", error);
		if (rcode)
			*rcode = error;
		return 0;
	}
	memcpy(&tm, rbuf + 4, 4);
	tm = ntohl(tm);
	if (tm + 20 < lasttm) {
		syslog(LOG_ERR, "add_redirect_rule2: server has rebootted");
		exit(0);
	}
	lasttm = tm;
	if (((rbuf[8] << 8) | rbuf[9]) != iport) {
		syslog(LOG_WARNING, "add_redirect_rule2: iport mismatch");
		return 0;
	}
	if (rcode) {
		eport = (rbuf[10] << 8) | rbuf[11];
	} else if (((rbuf[10] << 8) | rbuf[11]) != eport) {
		syslog(LOG_WARNING, "add_redirect_rule2: eport mismatch");
		return 0;
	}
	memcpy(&lt, rbuf + 12, 4);
	lt = ntohl(lt);
	return add_redirect_internal(eport, iaddr, iport, proto, lt, desc);
}

struct rdr *
get_redirect_rule(const char *ifname, unsigned short eport, int proto)
{
	return get_redirect_internal(eport, proto);
}	

struct rdr *
get_redirect_rule_by_index(int index, char *ifname)
{
	struct rdr *p = 0;
	int i = 0;

	for (p = rdr_list; p; p = p->next) {
		if (i == index)
			break;
		i++;
		}
	return p;
}

int
delete_redirect_rule(unsigned short eport, int proto)
{
	struct rdr *p;
	unsigned char buf[20];

	p = get_redirect_internal(eport, proto);
	if (!p)
		return -1;
	memset(buf, 0, sizeof(buf));
	buf[0] = 8;
	buf[1] = 'X';
	/* buf[2..3] = reserved; */
	if (inet_pton(AF_INET, p->iaddr, buf + 4) <= 0) {
		syslog(LOG_WARNING, "delete_(inet_pton)");
		del_redirect_internal(eport, proto);
		return -1;
	}
	/* buf[8] = version; */
	buf[9] = proto == IPPROTO_TCP ? 2 : 1;
	/* buf[10..11] = reserved; */
	buf[12] = p->iport >> 8;
	buf[13] = p->iport & 0xff;
	buf[14] = p->eport >> 8;
	buf[15] = p->eport & 0xff;
	/* buf[16..19] = lifetime; */
	if (send(sxfd6, buf, 20, 0) < 0)
		syslog(LOG_WARNING, "delete_(send): %m");
	del_redirect_internal(eport, proto);
	return 0;
}

int
delete_redirect_all(const char *iaddr, int proto)
{
	int r = 0;
	unsigned char buf[20];
	struct rdr *p, *last;

	memset(buf, 0, sizeof(buf));
	buf[0] = 8;
	buf[1] = 'X';
	/* buf[2..3] = reserved; */
	if (inet_pton(AF_INET, iaddr, buf + 4) <= 0) {
		syslog(LOG_WARNING, "delete_all(inet_pton)");
		r = -1;
		goto delrules;
	}
	/* buf[8] = version; */
	buf[9] = proto == IPPROTO_TCP ? 2 : 1;
	/* buf[10..11] = reserved; */
	/* buf[12..13] = iport; */
	/* buf[14..15] = eport; */
	/* buf[16..19] = lifetime; */
	if (send(sxfd6, buf, 20, 0) < 0) {
		syslog(LOG_WARNING, "delete_all(send): %m");
		r = -1;
	}
    delrules:
	p = rdr_list;
	last = 0;
	while (p) {
		if (strcmp(p->iaddr, iaddr) == 0 && p->proto == proto) {
			struct rdr *next = p->next;
			if (!last)
				rdr_list = next;
			else
				last->next = next;
			free(p);
			p = next;
		} else {
			last = p;
			p = p->next;
		}
	}
	return r;
}

void
AsyncGetPublicAddress(void)
{
	unsigned char buf[10];

	memset(buf, 0, sizeof(buf));
	buf[0] = 8;
	buf[1] = 'X';
	/* buf[2..3] = reserved; */
	/* buf[4..7] = iaddr; */
	/* buf[8] = version; */
	/* buf[9] = opcode_public_address_request; */
	if (send(sxfd6, buf, 10, 0) < 0)
		syslog(LOG_WARNING, "AsyncGetPublicAddress(send): %m");
}

void
ProcessXNATPMP(void)
{
	unsigned char buf[128];
	int cc, rcode;
	uint32_t tm, addr, prev;

	memset(buf, 0, sizeof(buf));
	cc = recv(sxfd6, buf, 128, 0);
	if (cc < 0) {
		syslog(LOG_WARNING, "ProcessXNATPMP(recv): %m");
		return;
	} else if (cc <= 11) {
		syslog(LOG_WARNING, "ProcessXNATPMP(recv): underrun");
		return;
	} else if (cc >= 100) {
		syslog(LOG_WARNING, "ProcessXNATPMP(recv): overrun");
		return;
	}
	if ((buf[0] != 8) ||
	    ((buf[1] != 'X') && (buf[1] != 'N') && (buf[1] != 'U'))) {
		syslog(LOG_WARNING, "ProcessXNATPMP: bad");
		return;
	}
	cc -= 8;
	memmove(buf, buf + 8, cc);
	if ((buf[0] != 0) || (buf[1] != 128) || (cc != 12)) {
		syslog(LOG_WARNING, "ProcessXNATPMP: skipping");
		return;
	}
	rcode = (buf[2] << 8) | buf[3];
	if (rcode != 0) {
		syslog(LOG_WARNING, "ProcessXNATPMP(rcode): %d", rcode);
		return;
	}
	memcpy(&tm, buf + 4, 4);
	tm = ntohl(tm);
	if (tm + 20 < lasttm) {
		syslog(LOG_ERR, "ProcessXNATPMP: server has rebootted");
		exit(0);
	}
	lasttm = tm;
	memcpy(&addr, buf + 8, 4);
	if (ext_ip_addr) {
		if ((inet_pton(AF_INET, ext_ip_addr, &prev) > 0) &&
		    (memcmp(&addr, &prev, 4) == 0))
			return;
		free(ext_ip_addr);
		ext_ip_addr = 0;
	}
	ext_ip_addr = malloc(INET_ADDRSTRLEN);
	if (!ext_ip_addr) {
		syslog(LOG_ERR, "ProcessXNATPMP(malloc): %m");
		return;
	}
	if (!inet_ntop(AF_INET, &addr, ext_ip_addr, INET_ADDRSTRLEN)) {
		syslog(LOG_ERR, "ProcessXNATPMP(inet_ntop)");
		return;
	}
	syslog(LOG_NOTICE, "new ext_ip_addr '%s'", ext_ip_addr);
	should_send_public_address_change_notif = 1;
}

int
refresh_redirect(struct rdr *r)
{
	unsigned char sbuf[20], rbuf[128];
	int cc, rcode;
	uint32_t tm, lt;

	memset(sbuf, 0, sizeof(sbuf));
	sbuf[0] = 8;
	sbuf[1] = 'X';
	cnt++;
	sbuf[2] = cnt >> 8;
	sbuf[3] = cnt & 0xff;
	if (inet_pton(AF_INET, r->iaddr, sbuf + 4) <= 0) {
		syslog(LOG_WARNING, "refresh_redirect(inet_pton)");
		return -3;
	}
	/* sbuf[8] = version; */
	sbuf[9] = r->proto == IPPROTO_TCP ? 4 : 3;
	/* sbuf[10..11] = reserved; */
	sbuf[12] = r->iport >> 8;
	sbuf[13] = r->iport & 0xff;
	sbuf[14] = r->eport >> 8;
	sbuf[15] = r->eport & 0xff;
	tm = htonl(r->lifetime);
	memcpy(sbuf + 16, &tm, 4);
	if (send(sxfd6, sbuf, 20, 0) < 0) {
		syslog(LOG_WARNING, "refresh_redirect(send): %m");
		return -3;
	}

	for (;;) {
		memset(rbuf, 0, sizeof(rbuf));
		cc = recv(sxfd6, rbuf, 128, MSG_PEEK);
		if (cc < 0) {
			syslog(LOG_WARNING, "refresh_redirect(recv): %m");
			return -3;
		}
		sbuf[9] += 128;
		if ((cc == 24) && (memcmp(sbuf, rbuf, 10) == 0))
			break;
		ProcessXNATPMP();
	}
	(void)recv(sxfd6, rbuf, 24, 0);
	cc -= 8;
	memmove(rbuf, rbuf + 8, cc);
	rcode = (rbuf[2] << 8) | rbuf[3];
	if (rcode != 0) {
		syslog(LOG_WARNING, "refresh_redirect(rcode): %d", rcode);
		return rcode;
	}
	memcpy(&tm, rbuf + 4, 4);
	tm = ntohl(tm);
	if (tm + 20 < lasttm) {
		syslog(LOG_ERR, "refresh_redirect: server has rebootted");
		exit(0);
	}
	lasttm = tm;
	if (((rbuf[8] << 8) | rbuf[9]) != r->iport) {
		syslog(LOG_WARNING, "refresh_redirect: iport mismatch");
		return -3;
	}
	if (((rbuf[10] << 8) | rbuf[11]) != r->eport) {
		syslog(LOG_WARNING, "refresh_redirect: eport mismatch");
		return -3;
	}
	memcpy(&lt, rbuf + 12, 4);
	lt = ntohl(lt);
	r->lifetime = lt;
	tm = (uint32_t)(time(NULL) - startup_time);
	if (r->expire)
		r->expire = tm + lt;
	if (r->refresh)
		r->refresh = tm + (3 * lt) / 4;
	return 0;
}

uint32_t
manage_redirects(uint32_t tm)
{
	struct rdr *r;
	int i;

	/* expire loop */
	i = 0;
	for(;;) {
		r = get_redirect_rule_by_index(i, 0);
		if (r == 0)
			break;
		if (r->expire != 0 && r->expire < tm)
			del_redirect_internal(r->eport, r->proto);
		else
			i++;
	}

	/* refresh loop */
	i = 0;
	for (;;) {
		r = get_redirect_rule_by_index(i, 0);
		if (r == 0)
			break;
		if (r->refresh != 0 && r->refresh < tm)
			(void) refresh_redirect(r);
		i++;
	}

	/* next refresh */
	tm = 0;
	i = 0;
	for (;;) {
		r = get_redirect_rule_by_index(i, 0);
		if (r == 0)
			break;
		if (r->refresh != 0 && (tm == 0 || r->refresh < tm))
			tm = r->refresh;
		i++;
	}
	return tm;
}
