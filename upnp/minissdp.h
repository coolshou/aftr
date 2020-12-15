/* $Id: minissdp.h,v 1.7 2008/10/06 13:20:56 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef __MINISSDP_H__
#define __MINISSDP_H__

int
OpenAndConfSSDPReceiveSocket();

int
OpenAndConfSSDPNotifySockets(int * sockets);

void
SendSSDPNotifies2(int * sockets,
                  unsigned short port,
                  unsigned int lifetime);

void
ProcessSSDPRequest(int s, unsigned short port);

int
SendSSDPGoodbye(int * sockets, int n);

int
SubmitServicesToMiniSSDPD(const char * host, unsigned short port);

#endif

