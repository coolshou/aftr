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

#ifndef __XNATPMP__
#define __XNATPMP__

#include "config.h"

/* init and shutdown functions */
int
init_redirect(void);

void
shutdown_redirect(void);

struct rdr *
get_redirect_rule(const char * ifname, unsigned short eport, int proto);

struct rdr *
get_redirect_rule_by_index(int index, char * ifname);

int
refresh_redirect(struct rdr *r);

struct rdr *
add_redirect_rule2(const char * ifname, unsigned short eport,
                   const char * iaddr, unsigned short iport,
		   int proto, unsigned int life,
		   const char * desc, unsigned short * rcode);

int
delete_redirect_rule(unsigned short eport, int proto);

int
delete_redirect_all(const char * iaddr, int proto);

uint32_t
manage_redirects(uint32_t tm);

void
AsyncGetPublicAddress(void);

void
ProcessXNATPMP(void);

#endif
