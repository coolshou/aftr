/* $Id: upnpredirect.c,v 1.49 2009/12/22 17:20:10 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2009 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include "config.h"
#include "upnpredirect.h"
#include "upnpglobalvars.h"
#include "upnpevents.h"
#include "xnatpmp.h"
#ifdef USE_MINIUPNPDCTL
#include <stdio.h>
#include <unistd.h>
#endif

/* proto_atoi() 
 * convert the string "UDP" or "TCP" to IPPROTO_UDP and IPPROTO_UDP */
static int
proto_atoi(const char * protocol)
{
	int proto = IPPROTO_TCP;
	if(strcmp(protocol, "UDP") == 0)
		proto = IPPROTO_UDP;
	return proto;
}

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
	      const char * desc)
{
	int proto;
	struct in_addr address;
	struct rdr *r;

	proto = proto_atoi(protocol);
	if(inet_aton(iaddr, &address) < 0) {
		syslog(LOG_ERR, "inet_aton(%s) : %m", iaddr);
		return -1;
	}

	if(!check_upnp_rule_against_permissions(upnppermlist, num_upnpperm,
	                                        eport, address, iport)) {
		syslog(LOG_INFO, "redirection permission check failed for "
		                 "%hu->%s:%hu %s", eport, iaddr, iport, protocol);
		return -3;
	}
	r = get_redirect_rule(ext_if_name, eport, proto);
	if(r != 0) {
		/* if existing redirect rule matches redirect request return success
		 * xbox 360 does not keep track of the port it redirects and will
		 * redirect another port when receiving ConflictInMappingEntry */
		if(strcmp(iaddr,r->iaddr)==0 && iport==r->iport) {
			syslog(LOG_INFO, "ignoring redirect request as it matches existing redirect");
		} else {

			syslog(LOG_INFO, "port %hu protocol %s already redirected to %s:%hu",
				eport, protocol, r->iaddr, r->iport);
			return -2;
		}
	} else {
		syslog(LOG_INFO,
		       "redirecting port %hu to %s:%hu protocol %s life %u for: %s",
		       eport, iaddr, iport, protocol, life, desc);			
		r = upnp_redirect_internal(eport, iaddr, iport, proto,
					   life, desc, NULL);
		if (r == 0)
			return -3;
		r->refresh = (3 * r->lifetime)/4 +
			(uint32_t)(time(NULL) - startup_time);
	}

	return 0;
}

struct rdr *
upnp_redirect_internal(unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, unsigned int life,
		       const char * desc,
		       unsigned short * rcode)
{
	struct rdr *r;

	r = add_redirect_rule2(ext_if_name, eport, iaddr, iport, proto,
			       life, desc, rcode);
#ifdef ENABLE_EVENTS
	if (r)
		upnp_event_var_change_notify(EWanIPC);
#endif
	return r;
}

struct rdr *
upnp_get_redirection_infos(unsigned short eport, const char * protocol)
{
	return get_redirect_rule(ext_if_name, eport, proto_atoi(protocol));
}

struct rdr *
upnp_get_redirection_infos_by_index(int index)
{
	return get_redirect_rule_by_index(index, 0/*ifname*/);
}

int
upnp_delete_redir_internal(unsigned short eport, int proto)
{
	int r;

	r = delete_redirect_rule(eport, proto);

#ifdef ENABLE_EVENTS
	upnp_event_var_change_notify(EWanIPC);
#endif
	return r;
}

int
upnp_delete_redirection(unsigned short eport, const char * protocol)
{
	syslog(LOG_INFO, "removing redirect rule port %hu %s", eport, protocol);
	return upnp_delete_redir_internal(eport, proto_atoi(protocol));
}

/* upnp_get_portmapping_number_of_entries()
 * TODO: improve this code */
int
upnp_get_portmapping_number_of_entries()
{
	struct rdr *r;
	int n = 0;
	do {
		r = upnp_get_redirection_infos_by_index(n);
		n++;
	} while(r != 0);
	return (n-1);
}

/* stuff for miniupnpdctl */
#ifdef USE_MINIUPNPDCTL
void
write_ruleset_details(int s)
{
	struct rdr *r;
	int i = 0;
	char buffer[256];
	int n;
	
	write(s, "Ruleset :\n", 10);
	while((r = get_redirect_rule_by_index(i, 0)) != 0) {
		n = snprintf(buffer, sizeof(buffer),
			     "%2d %s %hu->%s:%hu '%s'\n",
		             i, r->proto==IPPROTO_TCP?"TCP":"UDP",
		             r->eport, r->iaddr, r->iport, r->desc);
		write(s, buffer, n);
		i++;
	}
}
#endif

