/* $Id: natpmp.c,v 1.20 2010/05/06 13:42:47 nanard Exp $ */
/* MiniUPnP project
 * (c) 2007-2010 Thomas Bernard
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "config.h"
#include "natpmp.h"
#include "upnpglobalvars.h"
#include "getifaddr.h"
#include "upnpredirect.h"
#include "xnatpmp.h"

#ifdef ENABLE_NATPMP

int OpenAndConfNATPMPSocket(in_addr_t addr)
{
	int snatpmp;
	snatpmp = socket(PF_INET, SOCK_DGRAM, 0/*IPPROTO_UDP*/);
	if(snatpmp<0)
	{
		syslog(LOG_ERR, "socket(natpmp): %m");
		return -1;
	}
	else
	{
		struct sockaddr_in natpmp_addr;
		memset(&natpmp_addr, 0, sizeof(natpmp_addr));
		natpmp_addr.sin_family = AF_INET;
		natpmp_addr.sin_port = htons(NATPMP_PORT);
		//natpmp_addr.sin_addr.s_addr = INADDR_ANY;
		natpmp_addr.sin_addr.s_addr = addr;
		//natpmp_addr.sin_addr.s_addr = inet_addr("192.168.0.1");
		if(bind(snatpmp, (struct sockaddr *)&natpmp_addr, sizeof(natpmp_addr)) < 0)
		{
			syslog(LOG_ERR, "bind(natpmp): %m");
			close(snatpmp);
			return -1;
		}
	}
	return snatpmp;
}

int OpenAndConfNATPMPSockets(int * sockets)
{
	int i, j;
	for(i=0; i<n_lan_addr; i++)
	{
		sockets[i] = OpenAndConfNATPMPSocket(lan_addr[i].addr.s_addr);
		if(sockets[i] < 0)
		{
			for(j=0; j<i; j++)
			{
				close(sockets[j]);
				sockets[j] = -1;
			}
			return -1;
		}
	}
	return 0;
}

/** read the request from the socket, process it and then send the
 * response back.
 */
void ProcessIncomingNATPMPPacket(int s)
{
	unsigned char req[32];	/* request udp packet */
	unsigned char resp[32];	/* response udp packet */
	int resplen;
	struct sockaddr_in senderaddr;
	socklen_t senderaddrlen = sizeof(senderaddr);
	int n;
	char senderaddrstr[16];
	n = recvfrom(s, req, sizeof(req), 0,
	             (struct sockaddr *)&senderaddr, &senderaddrlen);
	if(n<0) {
		syslog(LOG_ERR, "recvfrom(natpmp): %m");
		return;
	}
	if(!inet_ntop(AF_INET, &senderaddr.sin_addr,
	              senderaddrstr, sizeof(senderaddrstr))) {
		syslog(LOG_ERR, "inet_ntop(natpmp): %m");
	}
	syslog(LOG_INFO, "NAT-PMP request received from %s:%hu %dbytes",
           senderaddrstr, ntohs(senderaddr.sin_port), n);
	if(n<2 || ((((req[1]-1)&~1)==0) && n<12)) {
		syslog(LOG_WARNING, "discarding NAT-PMP request (too short) %dBytes",
		       n);
		return;
	}
	if(req[1] & 128) {
		/* discarding NAT-PMP responses silently */
		return;
	}
	if (ext_ip_addr == 0) {
		AsyncGetPublicAddress();
		return;
	}
	memset(resp, 0, sizeof(resp));
	resplen = 8;
	resp[1] = 128 + req[1];	/* response OPCODE is request OPCODE + 128 */
	/* setting response TIME STAMP */
	*((uint32_t *)(resp+4)) = htonl(time(NULL) - startup_time);
	if(req[0] > 0) {
		/* invalid version */
		syslog(LOG_WARNING, "unsupported NAT-PMP version : %u",
		       (unsigned)req[0]);
		resp[3] = 1;	/* unsupported version */
	} else switch(req[1]) {
	case 0:	/* Public address request */
		syslog(LOG_INFO, "NAT-PMP public address request");
		inet_pton(AF_INET, ext_ip_addr, resp+8);
		resplen = 12;
		break;
	case 1:	/* UDP port mapping request */
	case 2:	/* TCP port mapping request */
		{
			unsigned short iport;	/* private port */
			unsigned short eport;	/* public port */
			uint32_t lifetime; 		/* lifetime=0 => remove port mapping */
			int r;
			int proto;
			struct rdr *rdr;

			iport = ntohs(*((uint16_t *)(req+4)));
			eport = ntohs(*((uint16_t *)(req+6)));
			lifetime = ntohl(*((uint32_t *)(req+8)));
			proto = (req[1]==1)?IPPROTO_UDP:IPPROTO_TCP;
			syslog(LOG_INFO, "NAT-PMP port mapping request : "
			                 "%hu->%s:%hu %s lifetime=%us",
			                 eport, senderaddrstr, iport,
			                 (req[1]==1)?"udp":"tcp", lifetime);
			if(lifetime == 0) {
				/* remove the mapping */
				if(iport == 0) {
					r = delete_redirect_all(senderaddrstr, proto);
					if(r<0) {
						syslog(LOG_ERR, "failed to remove port mappings");
						resp[3] = 2;	/* Not Authorized/Refused */
					} else {
						syslog(LOG_INFO, "NAT-PMP %s %s port mappings removed", proto==IPPROTO_TCP?"TCP":"UDP", senderaddrstr);
					}
				} else {
					/* To improve the interworking between nat-pmp and
					 * UPnP, we should check that we remove only NAT-PMP 
					 * mappings */
					r = upnp_delete_redir_internal(eport, proto);
					/*syslog(LOG_DEBUG, "%hu %d r=%d", eport, proto, r);*/
					if(r<0) {
						syslog(LOG_ERR, "Failed to remove NAT-PMP mapping eport %hu, protocol %s", eport, (proto==IPPROTO_TCP)?"TCP":"UDP");
						resp[3] = 2;	/* Not Authorized/Refused */
					}
				}
				eport = 0; /* to indicate correct removing of port mapping */
			} else if(iport==0
				  || !check_upnp_rule_against_permissions(upnppermlist, num_upnpperm, eport == 0 ? iport : eport, senderaddr.sin_addr, iport)) {
				resp[3] = 2;	/* Not Authorized/Refused */
			} else do {
				rdr = get_redirect_rule(ext_if_name, eport, proto);
				if(rdr != 0) {
					if(strcmp(senderaddrstr, rdr->iaddr)==0
				       && iport== rdr->iport) {
						/* redirection allready existing */
						syslog(LOG_INFO, "port %hu %s already redirected to %s:%hu, replacing", eport, (proto==IPPROTO_TCP)?"tcp":"udp", rdr->iaddr, rdr->iport);
						rdr->lifetime = lifetime;
						resp[3] = refresh_redirect(rdr);
					} else {
						eport++;
						continue;
					}
				}
				{ /* do the redirection */
					unsigned short rcode;

					if ((rdr = upnp_redirect_internal(eport, senderaddrstr,
									  iport, proto, (unsigned int) lifetime, "NAT-PMP", &rcode)) == NULL) {
						syslog(LOG_ERR, "Failed to add NAT-PMP %hu %s->%s:%hu 'NAT-PMP'",
						       eport, (proto==IPPROTO_TCP)?"tcp":"udp", senderaddrstr, iport);
						resp[3] = rcode;  /* Failure */
					} else {
						eport = rdr->eport;
						lifetime = rdr->lifetime;
					}
					break;
				}
			} while(rdr == 0);
			*((uint16_t *)(resp+8)) = htons(iport);	/* private port */
			*((uint16_t *)(resp+10)) = htons(eport);	/* public port */
			*((uint32_t *)(resp+12)) = htonl(lifetime);
		}
		resplen = 16;
		break;
	default:
		resp[3] = 5;	/* Unsupported OPCODE */
	}
	n = sendto(s, resp, resplen, 0,
	           (struct sockaddr *)&senderaddr, sizeof(senderaddr));
	if(n<0) {
		syslog(LOG_ERR, "sendto(natpmp): %m");
	} else if(n<resplen) {
		syslog(LOG_ERR, "sendto(natpmp): sent only %d bytes out of %d",
		       n, resplen);
	}
}

/* SendNATPMPPublicAddressChangeNotification()
 * should be called when the public IP address changed */
void SendNATPMPPublicAddressChangeNotification(int * sockets, int n_sockets)
{
	struct sockaddr_in sockname;
	unsigned char notif[12];
	int j, n;

	notif[0] = 0;
	notif[1] = 128;
	notif[2] = 0;
	notif[3] = 0;
	*((uint32_t *)(notif+4)) = htonl(time(NULL) - startup_time);
	inet_pton(AF_INET, ext_ip_addr, notif+8);
	if(notif[3])
	{
		syslog(LOG_WARNING, "%s: cannot get public IP address, stopping",
		       "SendNATPMPPublicAddressChangeNotification");
		return;
	}
	memset(&sockname, 0, sizeof(struct sockaddr_in));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(NATPMP_PORT);
	sockname.sin_addr.s_addr = inet_addr(NATPMP_NOTIF_ADDR);

	for(j=0; j<n_sockets; j++)
	{
		if(sockets[j] < 0)
			continue;
		n = sendto(sockets[j], notif, 12, 0,
		           (struct sockaddr *)&sockname, sizeof(struct sockaddr_in));
		if(n < 0)
		{	
			syslog(LOG_ERR, "%s: sendto(s_udp=%d): %m",
			       "SendNATPMPPublicAddressChangeNotification", sockets[j]);
			return;
		}
	}
}

#endif

