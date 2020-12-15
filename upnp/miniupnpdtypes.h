/* $Id: miniupnpdtypes.h,v 1.2 2008/01/27 22:24:39 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef __MINIUPNPDTYPES_H__
#define __MINIUPNPDTYPES_H__

#include "config.h"
#include <netinet/in.h>

/* structure for storing lan addresses
 * with ascii representation and mask */
struct lan_addr_s {
	char str[16];	/* example: 192.168.0.1 */
	struct in_addr addr, mask;	/* ip/mask */
};

/* per redirection structure */
struct rdr {
	struct rdr *next;
	uint32_t refresh;
	uint32_t expire;
	uint32_t lifetime;
	short proto;
	unsigned short iport;
	unsigned short eport;
	char iaddr[INET_ADDRSTRLEN];
	char desc[];
};

#endif
