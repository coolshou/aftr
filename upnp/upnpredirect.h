/* $Id: upnpredirect.h,v 1.15 2009/02/14 11:01:14 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __UPNPREDIRECT_H__
#define __UPNPREDIRECT_H__

#include "config.h"

/* upnp_redirect() 
 * calls OS/fw dependant implementation of the redirection.
 * protocol should be the string "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */
int
upnp_redirect(unsigned short eport, 
              const char * iaddr, unsigned short iport,
              const char * protocol, unsigned int life,
	      const char * desc);

struct rdr *
upnp_redirect_internal(unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, unsigned int life, const char * desc,
		       unsigned short * rcode);

/* upnp_get_redirection_infos() */
struct rdr *
upnp_get_redirection_infos(unsigned short eport, const char * protocol);

/* upnp_get_redirection_infos_by_index */
struct rdr *
upnp_get_redirection_infos_by_index(int index);

/* upnp_delete_redirection()
 * returns: 0 on success
 *          -1 on failure*/
int
upnp_delete_redirection(unsigned short eport, const char * protocol);

int
upnp_delete_redir_internal(unsigned short eport, int proto);

int
upnp_get_portmapping_number_of_entries();

/* stuff for responding to miniupnpdctl */
#ifdef USE_MINIUPNPDCTL
void
write_ruleset_details(int s);
#endif

#endif


