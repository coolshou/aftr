/*
 * Copyright (C) 2009-2010  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id: aftr.c 947 2010-10-20 04:52:03Z pselkirk $ */

/*
 * Dual-Stack Lite Carrier-Grade NAT
 *
 * Francis_Dupont@isc.org, November-December 2008
 *
 * Main structures are:
 *  - tunnels (fixed indexed vector, radix tree and hash table).
 *  - fragments (shared between IPv4/IPv6 and head/fragment,
 *   ordered by creation/expire time, heads in tailq, fragments in slist,
 *   IPv4 fragments are hashed). TODO: per tunnel reordering list +
 *   hash table dedicated to unknown tunnel (very low priority as
 *   fragments are supposed to be not common).
 *  - NAT entries (aka bindings) (red-black tree, per tunnel splay
 *   tree, expire heap and hash table) (support of static bindings with
 *   wildcard destination) (protocols: TCP, UDP and ICMP echo).
 *  - natted sources (available and reserved (to static bindings)).
 *
 * Routines:
 * (Utils)
 *  - *log* and *2str routines
 *  - print_iots (print I/O timestamp in "tcpdump -tt" format).
 *  - tun_read/tun_write (FreeBSD compatibility routines).
 *  - tun_open (the only OS-dependent routine, use P2P basic tun).
 *  - trace routine (create/delete tunnel/NAT events)
 *  - notify routine
 *  - random (from Open/FreeBSD arc4random)
 * (Data structures, basic)
 *  - Jenkins hash (specialized for per structure tables) with a random key.
 *   (from Linux but not under GPL)
 *  - red-black tree of NAT entries (from FreeBSD).
 *  - splay tree of per tunnel NAT entries (from FreeBSD).
 *  - heap for NAT entry expiration (from BIND9).
 *  - radix tree for tunnels (no support for prefixes aka descovery).
 *   (NOTE: internal nodes are tunnel structures with an impossible index).
 *   (from simplified Net-Patricia, GPL2, itself from BSD)
 * (Data structures, raw lookup/del/add/set...)
 * (Data structures, debug, print_* and check_*)
 * (Data structures, commands, add/del/...)
 * (Data structures, lists)
 * (Commands)
 *  - sub-commands (debug/default/delete/list/session)
 *  - dispatch and cmdline (config/command line)
 *  - commands (execute commands).
 *  - [re]load ([re]load config).
 * (Control channels)
 * (Packet utils)
 *  - checksum (very basic).
 *  - defrag/defrag6 (from simplified FreeBSD) (NOTE: no overlapping!).
 *  - patch_tcpmss (both way, syn tcp only).
 *  - tcpstate_in (detect closing)
 *  - tcpstate_out (detect closing)
 *  - get_ftptempdata (FTP DATA support)
 *  - patch_ftpcmd and ftpscan (FTP ALG)
 *  - patch_ftpin (FTP ALG from tunnel to Internet)
 * (IN: from tunnel)
 *  - filtericmpin (ICMP from tunnel to Internet, sanity only).
 *  - naticmpin (ICMPv4 from tunnel to Internet).
 *  - natin (from tunnel to Internet, lookup into the tunnel bindings,
 *   new_nat if not found).
 *  - prrin (strip down version of natin).
 *  - nonaticmpin (ICMPv6 translated to ICMPv4 from tunnel to Internet).
 *  - nonatin (NO-NAT support, only TCP MSS packet change)
 *  - filterin (IPv4 packets from tunnel, IPv6 filtering is implicit in
 *   tunnel decapsulation, sanity checks only). Source is checked for
 *   RFC 1918+I-D else PRR/A+P. (from FreeBSD)
 *  - icmp6in (ICMPv6 from tunnel, basic translation).
 *  - acl6 (ACL for IPv6)
 *  - acl4 (ACL for IPv4, private networks by default)
 *  - decap (tunnel decapsulation, tunnel lookup and sanity checks only).
 *   (NOTE: only one interface/device is needed).
 * (OUT: from Internet)
 *  - get_ftptempsrv (FTP ALG, server support)
 *  - patch_ftpout (FTP ALG from Internet to tunnel)
 *  - toobigout (unfragmentable from Internet, emit ICMPv4 error).
 *   TODO: rename into errorout and extend.
 *  - natout (from Internet to tunnel, hashed cached then red-black tree
 *   lookup, reorder tunnel bindings).
 *  - naticmpout (ICMPv4 from Internet to tunnel, same than natout on
 *   the included IPv4 packet, no reordering).
 *  - nonatout (NO-NAT support, handle toobig ICMPs and TCP MSS)
 *  - filtericmpout (ICMPv4 from Internet, sanity checks including error
 *   types). (from FreeBSD)
 *  - filterout (IPv4 from Internet, sanity checks, check destination
 *   (so natted) address). (from FreeBSD)
 *  - encap (tunnel encapsulation, trivial).
 *  (MAIN)
 *  - fork_child (child loop)
 *  - incremental garbage collection and backtrack
 *  - loop1 (one packet, instantaneous select, gettimeofday, read,
 *   for IPv6: decap, filterin, natin/prrin/nonatin, write,
 *   for IPv4: filterout, natout/naticmpout/nonatout, encap)
 *  - loop (main loop, reload, commands, loop1, gc/bt then
 *   expire bindings (using the heap) and fragments, resize hash tables).
 *  - init_hashes (initialize hash tables).
 *  - setup_start (call './aftr-script start', interface up, route all
 *   natted addresses to tun0, route the local IPv6 address to tun0).
 *   (NOTE: forget the point-to-point, in particular the shared peer address).
 *  - setup_stop (call './aftr-script stop', interface down).
 *  - reapchild (SIGCHLD handler)
 *  - inits (acl4 and sanity checks)
 *  - main (NOTE: no argument, never reach end).
 *
 * (other) TODO:
 *  - ECN copy. (NOTE: useful? mess checksum).
 *
 * Testing:
 *  - checksums: should be good when used
 *  - defrag: right on correct packets
 *  - nat: lookup/add_snat correct (port redirection)
 *  - nat heap: correct
 *  - nat tree: seems to work
 *  - filterin/natin/new_nat: works (note: beware of iptables: disable them)
 *  - filtericmpin/naticmpin/icmp6in: works
 *   (ICMP dropped by Linux kernel with spurious anti-spoof if the icmpsrc
 *    address is 10.0.100.1, works without problems with 10.0.100.2 or on
 *    FreeBSD)
 *  - toobigout: same partial issue than icmp6in
 *  - filterout/natout: works (both at natin reversal and port redirection)
 *  - filtericmpout/naticmpout: works
 *  - tunnel tree: seems to work
 *  - encap: works (including fragmentation)
 *  - decap: works (including reassembly)
 *  - load: works
 *  - hairpin (i.e., client to client): works (through double mapping)
 *  - tcpmss: patched (both ways)
 *  - commands: works (including extended debug, delete, list and trace)
 *  - a+p/prr: works (don't forget to add the address)
 *  - tcp closing: works
 *
 * Control flow:
 *
 *    loop()
 *     |
 *     V
 *    incremental reload
 *     |
 *     |          /-> commands()
 *     V         /                            /-> IPv6 read
 *    select() -+--->loop1()---> tun_read() -+
 *     |                                      \-> IPv4 read
 *     V
 *    incremental garbage collection/backtrack
 *     |
 *     V
 *    every second -> rates & expire (NAT heap, IPv4 fragments, IPv6 fragments)
 *     |
 *     V
 *    every 256 seconds -> resize hash tables
 *                         (caches: fragments, NAT entries, tunnels)
 *
 *    IPv6 read:
 *     |
 *     V 
 *    decap() (sanity checks (IPv6), acl6(), icmp6in(), tunnel lookup/add,
 *     |       defrag6(), tel strip)
 *     |
 *     +---> icmp6in() (sanity check, classify, tunnel lookup)
 *     |      |
 *     |      +--> set_tunnel_mtu()
 *     |      |
 *     |      V
 *     |     naticmpin/nonaticmpin() (for translation to ICMPv4)
 *     V
 *    filterin() (sanity checks (IPv4), defrag(), classify)
 *     |   |
 *     |   | (ICMP not EchoRequest, RFC 1918+I-D source, default case)
 *     |   +--+--+
 *     |   |  |  |
 *     |   |  |  \-----> natin()
 *     |   |  |             |
 *     |   |  \---> prrin() |
 *     |   V          |     |
 *     |  nonatin() --+-----+-> tun_write() (translated IPv4 standard packet)
 *     V
 *    naticmpin()
 *
 *    natin()
 *     |
 *     V
 *    NAT entry lookup/add
 *     |
 *     V
 *    translation (source <- mapped, fix checksums, for TCP patch MSS,
 *     |           FTP ALG and detect state needing shorter timeouts)
 *     V
 *    housekeeping (expiration heap, per tunnel NAT entry list reordering)
 *
 *    prrin()
 *     |
 *     V
 *    (PRR/A+P) NAT entry lookup (and NAT entry list reordering)
 *
 *    nonatin()
 *     |
 *     V
 *    NO-NAT (nearly nothing)
 *
 *    naticmpin()
 *     |
 *     V
 *    ICMPv4 header stripping
 *     |
 *     V
 *    filtericmpin() (sanity check, keep types 3/11/12)
 *     |
 *     V
 *    NAT entry lookup (on triggering packet)
 *     |
 *     V
 *    translate/build ICMP header
 *     |
 *     V
 *    translate triggering packet
 *     |
 *     V
 *    tun_write() (translated ICMPv4 error packet)
 *
 *    IPv4 read
 *     |
 *     V
 *    filterout()
 *     |
 *     +--> natout() -----+-> encap() (encapsulate/fragment)
 *     |                  |    |         
 *     +--> naticmpout() -+    V
 *     |                  |   tun_write() (encapsulating IPv6 packet/fragment)
 *     \--> nonatout() ---/
 *
 *    filterout()
 *     |
 *     V
 *    sanity checks (including on destination address), defrag()
 *     |
 *     V
 *    classify --> filtericmpout() (ICMP not EchoReply, error 3/11/12,
 *     |                            sanity checks on triggering packet)
 *     \
 *      \-> drop, standard or ICMP
 *
 *    natout()
 *     |
 *     V
 *    NAT entry lookup (including PRR/A+P case detection)
 *     |
 *     +--> toobigout() (DF packet > MTU, reflect ICMPv4 toobig)
 *     |
 *     V
 *    translation (destination <- original, fix checksums, for TCP patch MSS,
 *     |           FTP ALG and detect state needing shorter timeouts)
 *     V
 *    housekeeping (expiration heap, per tunnel NAT entry list reordering)
 *
 *    naticmpout()
 *     |
 *     V
 *    NAT entry lookup (including PRR/A+P case detection)
 *     |
 *     V
 *    translation (ICMP and triggering packet)
 *
 *    nonatout()
 *     |
 *     V
 *    NO-NAT (nearly nothing)
 */

#define _GNU_SOURCE
#ifndef __linux__
#include <sys/types.h>
#include <sys/uio.h>
#endif
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifndef __linux__
#include <net/if.h>
#include <net/if_tun.h>
#else
#include <linux/if.h>
#include <linux/if_tun.h>
#ifndef ETH_P_IP
#include <linux/if_ether.h>
#endif
#endif

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* Local macros */

#define ISC_DECR(cnt, name)						\
	do {								\
		if (cnt == 0)						\
			logcrit("%s goes under 0\n", name);		\
		else							\
			cnt -= 1;					\
	} while (0)

/* Local macros */

#define ISC_SLIST_HEAD(name, type)					\
	struct name {							\
		struct type *slh_first;					\
	}

#define ISC_SLIST_INIT(head)						\
	do {								\
		(head)->slh_first = NULL;				\
	} while (0)

#define ISC_SLIST_ENTRY(type)						\
	struct {							\
		struct type *sle_next;					\
	}

#define ISC_SLIST_EMPTY(head)						\
	((head)->slh_first == NULL)

#define ISC_SLIST_FIRST(head)						\
	((head)->slh_first)

#define ISC_SLIST_NEXT(elm, field)					\
	((elm)->field.sle_next)

#define ISC_SLIST_INSERT_HEAD(head, elm, field)				\
	do {								\
		(elm)->field.sle_next = (head)->slh_first;		\
		(head)->slh_first = (elm);				\
	} while (0)

#define ISC_SLIST_INSERT_AFTER(elm0, elm, field)			\
	do {								\
		(elm)->field.sle_next = (elm0)->field.sle_next;		\
		(elm0)->field.sle_next = (elm);				\
	} while (0)

#define ISC_SLIST_REMOVE_HEAD(head, field)				\
	do {								\
		(head)->slh_first = (head)->slh_first->field.sle_next;	\
	} while (0)

#define ISC_SLIST_REMOVE(head, elm, type, field)			\
	do {								\
		if ((head)->slh_first == (elm)) {			\
			ISC_SLIST_REMOVE_HEAD(head, field);		\
		} else {						\
			struct type *cur = (head)->slh_first;		\
			while (cur->field.sle_next != (elm))		\
				cur = cur->field.sle_next;		\
			cur->field.sle_next = (elm)->field.sle_next;	\
		}							\
	} while (0)

#define ISC_SLIST_FOREACH(var, head, field)				\
	for ((var) = (head)->slh_first;					\
	     (var) != NULL;						\
	     (var) = (var)->field.sle_next)

#define ISC_SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = (head)->slh_first;					\
	     ((var) != NULL) &&	(((tvar) = (var)->field.sle_next), 1);	\
	     (var) = (tvar))

#define ISC_STAILQ_HEAD(name, type)					\
	struct name {							\
		struct type *stqh_first;				\
		struct type **stqh_last;				\
	}

#define ISC_STAILQ_INIT(head)						\
	do {								\
		(head)->stqh_first = NULL;				\
		(head)->stqh_last = &(head)->stqh_first;		\
	} while (0)

#define ISC_STAILQ_ENTRY(type)						\
	struct {							\
		struct type *stqe_next;					\
	}

#define ISC_STAILQ_EMPTY(head)						\
	((head)->stqh_first == NULL)

#define ISC_STAILQ_FIRST(head)						\
	((head)->stqh_first)

#define ISC_STAILQ_LAST(head, type, field)				\
	((head)->stqh_first == NULL ? NULL :				\
		((struct type *)(void *)				\
		 ((char *)((head)->stqh_last) -				\
		  __offsetof(struct typem field))))

#define ISC_STAILQ_NEXT(elm, field)					\
	((elm)->field.stqe_next)

#define ISC_STAILQ_INSERT_HEAD(head, elm, field)			\
	do {								\
		(elm)->field.stqe_next = (head)->stqh_first;		\
		if ((head)->stqh_first == NULL)				\
			(head)->stqh_last = &(elm)->field.stqe_next;	\
		(head)->stqh_first = (elm);				\
	} while (0)

#define ISC_STAILQ_INSERT_TAIL(head, elm, field)			\
	do {								\
		(elm)->field.stqe_next = NULL;				\
		*(head)->stqh_last = (elm);				\
		(head)->stqh_last = &(elm)->field.stqe_next;		\
	} while (0)

#define ISC_STAILQ_REMOVE_HEAD(head, field)				\
	do {								\
		(head)->stqh_first =					\
			(head)->stqh_first->field.stqe_next;		\
		if ((head)->stqh_first == NULL)				\
			(head)->stqh_last = &(head)->stqh_first;	\
	} while (0)

#define ISC_STAILQ_REMOVE(head, elm, type, field)			\
	do {								\
		if ((head)->stqh_first == (elm)) {			\
			ISC_STAILQ_REMOVE_HEAD(head, field);		\
		} else {						\
			struct type *cur = (head)->stqh_first;		\
			while (cur->field.stqe_next != (elm))		\
				cur = cur->field.stqe_next;		\
			cur->field.stqe_next = (elm)->field.stqe_next;	\
			if (cur->field.stqe_next == NULL)		\
				(head)->stqh_last =			\
					&cur->field.stqe_next;		\
		}							\
	} while (0)

#define ISC_STAILQ_FOREACH(var, head, field)				\
	for ((var) = (head)->stqh_first;				\
	     (var) != NULL;						\
	     (var) = (var)->field.stqe_next)

#define ISC_STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = (head)->stqh_first;				\
	     ((var) != NULL) && (((tvar) = (var)->field.stqe_next), 1);	\
	     (var) = (tvar))

#define ISC_LIST_HEAD(name, type)					\
	struct name {							\
		struct type *lh_first;					\
	}

#define ISC_LIST_INIT(head)						\
	do {								\
		(head)->lh_first = NULL;				\
	} while (0)

#define ISC_LIST_ENTRY(type)						\
	struct {							\
		struct type *le_next;					\
		struct type **le_prev;					\
	}

#define ISC_LIST_EMPTY(head)						\
	((head)->lh_first == NULL)

#define ISC_LIST_FIRST(head)						\
	((head)->lh_first)

#define ISC_LIST_NEXT(elm, field)					\
	((elm)->field.le_next)

#define ISC_LIST_PREV(elm, field)					\
	((elm)->field.le_prev)

#define ISC_LIST_INSERT_HEAD(head, elm, field)				\
	do {								\
		(elm)->field.le_next = (head)->lh_first;		\
		if ((head)->lh_first != NULL)				\
			(head)->lh_first->field.le_prev =		\
				&(elm)->field.le_next;			\
		(head)->lh_first = (elm);				\
		(elm)->field.le_prev = &(head)->lh_first;		\
	} while (0)

#define ISC_LIST_REMOVE(elm, field)					\
	do {								\
		if ((elm)->field.le_next != NULL)			\
			(elm)->field.le_next->field.le_prev =		\
				(elm)->field.le_prev;			\
		*(elm)->field.le_prev = (elm)->field.le_next;		\
		(elm)->field.le_next = NULL;				\
		(elm)->field.le_prev = NULL;				\
	} while (0)

#define ISC_LIST_FOREACH(var, head, field)				\
	for ((var) = (head)->lh_first;					\
	     (var) != NULL;						\
	     (var) = (var)->field.le_next)

#define ISC_LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = (head)->lh_first;					\
	     ((var) != NULL) &&	(((tvar) = (var)->field.le_next), 1);	\
	     (var) = (tvar))

#define ISC_TAILQ_HEAD(name, type)					\
	struct name {							\
		struct type *tqh_first;					\
		struct type **tqh_last;					\
	}

#define ISC_TAILQ_INIT(head)						\
	do {								\
		(head)->tqh_first = NULL;				\
		(head)->tqh_last = &(head)->tqh_first;			\
	} while (0)

#define ISC_TAILQ_ENTRY(type)						\
	struct {							\
		struct type *tqe_next;					\
		struct type **tqe_prev;					\
	}

#define ISC_TAILQ_EMPTY(head)						\
	((head)->tqh_first == NULL)

#define ISC_TAILQ_FIRST(head)						\
	((head)->tqh_first)

#define ISC_TAILQ_LAST(head, type)					\
	(*(((struct type *)((head)->tqh_last))->tqh_last))

#define ISC_TAILQ_NEXT(elm, field)					\
	((elm)->field.tqe_next)

#define ISC_TAILQ_INSERT_HEAD(head, elm, field)				\
	do {								\
		(elm)->field.tqe_next = (head)->tqh_first;		\
		if ((head)->tqh_first != NULL)				\
			(head)->tqh_first->field.tqe_prev =		\
				&(elm)->field.tqe_next;			\
		else							\
			(head)->tqh_last = &(elm)->field.tqe_next;	\
		(head)->tqh_first = (elm);				\
		(elm)->field.tqe_prev = &(head)->tqh_first;		\
	} while (0)

#define ISC_TAILQ_INSERT_TAIL(head, elm, field)				\
	do {								\
		(elm)->field.tqe_next = NULL;				\
		(elm)->field.tqe_prev = (head)->tqh_last;		\
		*(head)->tqh_last = (elm);				\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	} while (0)

#define ISC_TAILQ_REMOVE(head, elm, field)				\
	do {								\
		if ((elm)->field.tqe_next != NULL)			\
			(elm)->field.tqe_next->field.tqe_prev =		\
				(elm)->field.tqe_prev;			\
		else							\
			(head)->tqh_last = (elm)->field.tqe_prev;	\
		*(elm)->field.tqe_prev = (elm)->field.tqe_next;		\
		(elm)->field.tqe_next = NULL;				\
		(elm)->field.tqe_prev = NULL;				\
	} while (0)

#define ISC_TAILQ_FOREACH(var, head, field)				\
	for ((var) = (head)->tqh_first;					\
	     (var) != NULL;						\
	     (var) = (var)->field.tqe_next)

#define ISC_TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = (head)->tqh_first;					\
	     ((var) != NULL) && (((tvar) = (var)->field.tqe_next), 1);	\
	     (var) = (tvar))

#ifdef SIGNSHDR
typedef struct {
	char magic[4];
} isc_magic_t;

#define ISC_MAGIC_CHECK(x, sig)						\
	do {								\
		isc_magic_t *m = (isc_magic_t *) (x);			\
		if (m == NULL)						\
			logcrit("NULL for %s\n", (sig));		\
		if (((sig)[0] != m->magic[0]) ||			\
		    ((sig)[1] != m->magic[1]) ||			\
		    ((sig)[2] != m->magic[2]) ||			\
		    ((sig)[3] != '\0'))					\
			logcrit("bad magic for %lx "			\
				"(%c%c%c%c != %s)\n",			\
				m->magic[0], m->magic[1],		\
				m->magic[2], m->magic[3],		\
				(sig));					\
	} while (0)

#define ISC_MAGIC_SET(x, sig)						\
	do {								\
		isc_magic_t *m = (isc_magic_t *) (x);			\
		if (m == NULL)						\
			logcrit("NULL for %s\n", (sig));		\
		m->magic[0] = (sig)[0];					\
		m->magic[1] = (sig)[1];					\
		m->magic[2] = (sig)[2];					\
		m->magic[3] = '\0';					\
	} while (0)

#define ISC_MAGIC_FREE(x, sig)						\
	do {								\
		isc_magic_t *m = (isc_magic_t *) (x);			\
		if (m == NULL)						\
			logcrit("NULL for %s\n", (sig));		\
		if (((sig)[0] != m->magic[0]) ||			\
		    ((sig)[1] != m->magic[1]) ||			\
		    ((sig)[2] != m->magic[2]) ||			\
		    ((sig)[3] != '\0'))					\
			logcrit("bad magic for %lx "			\
				"(%c%c%c%c != %s)\n",			\
				m->magic[0], m->magic[1],		\
				m->magic[2], m->magic[3],		\
				(sig));					\
		m->magic[3] = 'F';					\
	} while (0)

#else
#define ISC_MAGIC_CHECK(x, sig)
#define ISC_MAGIC_SET(x, sig)
#define ISC_MAGIC_FREE(x, sig)
#endif

#define ISC_ACL6_MAGIC		"ACL"
#define ISC_FRAGMENT_MAGIC	"FRG"
#define ISC_FTPSEQ_MAGIC	"FTP"
#define ISC_HELD_MAGIC		"HLD"
#define ISC_NAT_MAGIC		"NAT"
#define ISC_POOL_MAGIC		"POO"
#define ISC_ACL4_MAGIC		"PRI"
#define ISC_SESSION_MAGIC	"SES"
#define ISC_TUNNEL_MAGIC	"TLN"

#ifndef QUANTUM
#define QUANTUM		20
#endif
#if (QUANTUM <= 1) || (QUANTUM > 255)
#error bad QUANTUM
#endif
u_char quantum = QUANTUM;

/* Offsets and interesting constants for IPv4, ICMPv4, UDP, TCP,
 * IPv6 and v6 Fragment structures */

#define IPTOS		1
#define IPLENH		2
#define IPLENL		3
#define IPID		4
#define IPOFFH		6
#define IPOFFL		7
#define IPTTL		8
#define IPPROTO		9
#define IPCKSUMH	10
#define IPCKSUML	11
#define IPSRC		12
#define IPDST		16
#define IPSPORT		20
#define IPDPORT		22

#define ICMPTYPE	20
#define ICMPCODE	21
#define ICMPCKSUMH	22
#define ICMPCKSUML	23
#define ICMPID		24
#define IP2		28
#define IP2LENH		(IP2 + IPLENH)
#define IP2LENL		(IP2 + IPLENL)
#define IP2OFFH		(IP2 + IPOFFH)
#define IP2OFFL		(IP2 + IPOFFL)
#define IP2PROTO	(IP2 + IPPROTO)
#define IP2CKSUMH	(IP2 + IPCKSUMH)
#define IP2CKSUML	(IP2 + IPCKSUML)
#define IP2SRC		(IP2 + IPSRC)
#define IP2DST		(IP2 + IPDST)
#define IP2SPORT	(IP2 + IPSPORT)
#define IP2DPORT	(IP2 + IPDPORT)

#define UDPLEN		(IPHDRLEN + 4)
#define UDPCKSUMH	(IPHDRLEN + 6)
#define UDPCKSUML	(IPHDRLEN + 7)

#define TCPSEQ		(IPHDRLEN + 4)
#define TCPACK		(IPHDRLEN + 8)
#define TCPOFF		(IPHDRLEN + 12)
#define TCPFLAGS	(IPHDRLEN + 13)
#define TCPCKSUMH	(IPHDRLEN + 16)
#define TCPCKSUML	(IPHDRLEN + 17)

#define IPVERMSK	0xf0
#define IP4V		0x40
#define IP4VNOOP	0x45
#define IPHDRLEN	20
#define IPMINLEN	28
#define IPMAXLEN	65535
#define IPDF		0x40
#define IPMF		0x20
#define IPOFFMSK	0x1f

#define IPICMP		1
#define IPTCP		6
#define IPUDP		17

#define PORTFTP		21

#define ICMPECHREP	0
#define ICMPECHREQ	8

#define TCPHDRLEN	20
#define TCPOFFMSK	0xf0
#define TCPFFIN		0x01
#define TCPFSYN		0x02
#define TCPFRST		0x04
#define TCPFACK		0x10
#define TCPOPTEOL	0
#define TCPOPTNOP	1
#define TCPOPTMSS	2
#define TCPOPTMSSLEN	4
#define TCPOPTMD5	19

#define IP6V		0x60
#define IP6LENH		4
#define IP6LENL		5
#define IP6PROTO	6
#define IP6TTL		7
#define IP6SRC		8
#define IP6DST		24
#define IP6HDRLEN	40

#define IP6FPROTO	40
#define IP6FOFFH	42
#define IP6FOFFL	43
#define IP6FID		44

#define IP6FLEN		(IP6HDRLEN + 8)
#define IP6FMF		0x01
#define IP6FMSK		0xf8

#define ICMP6TYPE	40
#define ICMP6CODE	41
#define ICMP6CKSUMH	42
#define ICMP6CKSUML	43
#define ICMP6PTR	44
#define IP62PROTO	54
#define IP62SRC		56
#define IP62DST		72
#define IP64		88
#define IP64PROTO	(IP64 + IPPROTO)

#define IP6OTEL		0x04

#define IP6IP4		4
#define IP6FRAG		44
#define IP6DSTOP	50
#define IP6ICMP		58

#define ICMPMAXLEN	200

/* exp(-1/{60,300,900}) for 1mn, 5mn, 15mn decays */
#ifndef DECAY1
#define DECAY1	.98347145382161748948
#endif
#ifndef DECAY5
#define DECAY5	.99667221605452332152
#endif
#ifndef DECAY15
#define DECAY15	.99888950594427931322
#endif

double decays[3] = { DECAY1, DECAY5, DECAY15 };

/* file names */

#ifndef AFTRSCRIPT
#define AFTRSCRIPT	"./aftr-script"
#endif
#ifndef AFTRCONFIG
#define AFTRCONFIG	"aftr.conf"
#endif
#ifndef AFTRDEVICE
#define AFTRDEVICE	"tun0"
#endif

char *aftrconfig;
char *aftrscript;
char *setup_cmd;
char *aftrdevice;
char tunname[64];
int tunfd;

#ifndef AFTRLOGOPTION
#define AFTRLOGOPTION	LOG_NDELAY
#endif
#ifndef AFTRFACILITY
#define AFTRFACILITY	LOG_LOCAL5
#endif

#define DR_BAD6		0	/* bad IPv6 packet */
#define DR_ACL6		1	/* filtered by IPv6 ACL */
#define DR_NOTUN	2	/* no tunnel */
#define DR_ICMP6	3	/* bad/uninteresting ICMPv6 packet */
#define DR_BADIN	4	/* bad IPv4 in packet */
#define DR_INGRESS	5	/* bad PRR/NoNAT IPv4 in packet */
#define DR_NATCNT	6	/* too many NAT */
#define DR_NATRT	7	/* NAT creation rate limit */
#define DR_NEWNAT	8	/* can't create a new NAT */
#define DR_ICMPIN	9	/* bad/uninteresting ICMPv4 in packet */
#define DR_BADOUT	10	/* bad IPv4 out packet */
#define DR_DSTOUT	11	/* bad destination address, out packet */
#define DR_ICMPOUT	12	/* bad/uninteresting ICMPv4 out packet */
#define DR_NATOUT	13	/* no NAT matching IPv4 out packet */
#define DR_TOOBIG	14	/* DF too big IPv4 out packet */
#define DR_F6CNT	15	/* too many IPv6 fragments */
#define DR_F6TCNT	16	/* too many IPv6 fragments per tunnel */
#define DR_BADF6	17	/* bad IPv6 fragment */
#define DR_F6TM		18	/* IPv6 fragment timeout */
#define DR_FINCNT	19	/* too many IPv4 in fragments */
#define DR_FINTCNT	20	/* too many IPv4 in fragments per tunnel */
#define DR_FOUTCNT	21	/* too many IPv4 out fragments */
#define DR_BADF4	22	/* bad IPv4 fragment */
#define DR_F4MEM	23	/* IPv4 fragment alloc pb */
#define DR_FINTM	24	/* IPv4 in fragment timeout */
#define DR_FOUTTM	25	/* IPv4 out fragment timeout */
#define DR_MAX		25	/* max dropped reason */

char *dropreason[DR_MAX + 1] = {
	"bad IPv6 packet",
	"filtered by IPv6 ACL",
	"no tunnel",
	"bad/uninteresting ICMPv6 packet",
	"bad IPv4 'in' packet",
	"filtered by IPv4 ingress PRR / NoNat",
	"too many NAT entries for tunnel",
	"NAT entry creation rate limited",
	"can't create a new NAT entry",
	"bad/uninteresting ICMPv4 'in' packet",
	"bad IPv4 'out' packet",
	"'out' packet with a bad destination address",
	"bad/uninteresting ICMPv4 'out' packet",
	"no NAT matching IPv4 'out' packet",
	"DF and too big IPv4 'out' packet",
	"too many IPv6 fragments",
	"too many IPv6 fragments per tunnel",
	"bad IPv6 fragment",
	"IPv6 fragment timeout",
	"too many IPv4 'in' fragments",
	"too many IPv4 'in' fragments per tunnel",
	"too many IPv4 'out' fragments",
	"bad IPv4 fragment",
	"IPv4 fragment allocation failure",
	"IPv4 'in' fragment timeout",
	"IPv4 'out' fragment timeout"
};

uint64_t statsrcv6, statsrcv4, statssent6, statssent4;
uint64_t statsfrgin6, statsfrgin, statsfrout, statsfrgout6;
uint64_t statsreas6, statsreasin, statsreasout;
uint64_t statsnatin, statsprrin, statsnonatin;
uint64_t statsnaticmpin6, statsnaticmpin4;
uint64_t statsnatout, statsprrout, statsnonatout, statsnaticmpout;
uint64_t statstcpmss, statsmsspatched, statstoobig;
uint64_t statsftpport, statsftpeprt, statsftp227, statsftp229;
uint64_t statscnat, statsdnat;
uint64_t statsdropped[DR_MAX + 1];

uint64_t debugrcv6, debugrcv4, debugsent6, debugsent4;
uint64_t debugfrgin6, debugfrgin, debugfrgout6, debugreas6, debugreasin;
uint64_t debugnatin, debugprrin, debugnonatin;
uint64_t debugnaticmpin6, debugnaticmpin4;
uint64_t debugnatout, debugprrout, debugnonatout, debugnaticmpout;
uint64_t debugtcpmss, debugmsspatched, debugtoobig;
uint64_t debugftpport, debugftpeprt, debugftp227, debugftp229;
uint64_t debugcnat, debugdnat;
uint64_t debugdropped[DR_MAX + 1];

uint64_t lastrcv6, lastrcv4, lastsent6, lastsent4;
uint64_t lastcnat, lastdnat;
double ratercv6[3], ratercv4[3], ratesent6[3], ratesent4[3];
double ratecnat[3], ratednat[3];

u_char buf4[66000], buf6[66000], buf[1500];
u_int len;

time_t seconds, lastsecs, startsecs;

u_char icmpsrc[4];			/* interface address (for ICMP) */
int icmpsrc_set = 0;
u_char local6[16];			/* local IPv6 address */
int local6_set = 0;

int eqfrag = 0;
int use_autotunnel = 1;
int debuglevel = 0;

#ifndef FRAG_LIFETIME
#define FRAG_LIFETIME	30
#endif
#if (FRAG_LIFETIME <= 0) || (FRAG_LIFETIME > 1200)
#error bad FRAG_LIFETIME
#endif

u_int frag_lifetime = FRAG_LIFETIME;

#ifndef FRAG6_MAXCNT
#define FRAG6_MAXCNT	1024
#endif
#if (FRAG6_MAXCNT < 0) || (FRAG6_MAXCNT > 16535)
#error bad FRAG6_MAXCNT
#endif
#ifndef FRAGIN_MAXCNT
#define FRAGIN_MAXCNT	1024
#endif
#if (FRAGIN_MAXCNT < 0) || (FRAGIN_MAXCNT > 16535)
#error bad FRAGIN_MAXCNT
#endif
#ifndef FRAGOUT_MAXCNT
#define FRAGOUT_MAXCNT	1024
#endif
#if (FRAGOUT_MAXCNT < 0) || (FRAGOUT_MAXCNT > 16535)
#error bad FRAGOUT_MAXCNT
#endif

u_int frag_maxcnt[3] = { FRAG6_MAXCNT, FRAGIN_MAXCNT, FRAGOUT_MAXCNT };

#ifndef FRAGTN6_MAXCNT
#define FRAGTN6_MAXCNT	16
#endif
#if (FRAGTN6_MAXCNT <= 0) || (FRAGTN6_MAXCNT > 255)
#error bad FRAGTN6_MAXCNT
#endif
#ifndef FRAGTN4_MAXCNT
#define FRAGTN4_MAXCNT	64
#endif
#if (FRAGTN4_MAXCNT <= 0) || (FRAGTN4_MAXCNT > 255)
#error bad FRAGTN6_MAXCNT
#endif

u_char fragtn_maxcnt[2] = { FRAGTN6_MAXCNT, FRAGTN4_MAXCNT };

struct firsthdr {
	ISC_TAILQ_ENTRY(frag) chain;	/* chaining (tailq) */
	ISC_SLIST_HEAD(, frag) list;	/* in packet fragment (first only) */
};
struct fraghdr {
	ISC_SLIST_ENTRY(frag) chain;	/* chaining (slist) */
};

struct frag {				/* fragment entry */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	union {
		struct firsthdr _fhdr;
		struct fraghdr _hdr;
	} _fuhdr;
#define ffragchain	_fuhdr._fhdr.chain
#define fraglist	_fuhdr._fhdr.list
#define fragchain	_fuhdr._hdr.chain
	struct tunnel *tunnel;		/* reference to tunnel (or NULL) */
	u_char *buf;			/* buffer copy */
	u_int len;			/* buffer (full) length */
	u_int off;			/* fragment offset */
	time_t expire;			/* expiration date (first only) */
	u_short hash;			/* last hash (first only) */
	u_char more;			/* more flag */
};
ISC_TAILQ_HEAD(fragshead, frag)
	frags6,				/* IPv6 global fragment tailq */
	fragsin,			/* IPv4 in global fragment tailq */
	fragsout;			/* IPv4 out global fragment tailq */
u_int frags6cnt;			/* IPv6 fragment count */
u_int fragsincnt;			/* IPv4 in fragment count */
u_int fragsoutcnt;			/* IPv4 out fragment count */

#define TCPPR	0
#define UDPPR	1
#define ICMPPR	2
#define PRCNT	3

#ifndef TCP_MINPORT
#define TCP_MINPORT	2048
#endif
#ifndef UDP_MINPORT
#define UDP_MINPORT	512
#endif
#ifndef ICMP_MINID
#define ICMP_MINID	0
#endif
#ifndef TCP_MAXPORT
#define TCP_MAXPORT	65535
#endif
#ifndef UDP_MAXPORT
#define UDP_MAXPORT	65535
#endif
#ifndef ICMP_MAXID
#define ICMP_MAXID	65535
#endif
#if (TCP_MINPORT <= 0) || (TCP_MAXPORT > 65535) || (TCP_MINPORT > TCP_MAXPORT)
#error "bad TCP_[MIN|MAX]PORT"
#endif
#if (UDP_MINPORT <= 0) || (UDP_MAXPORT > 65535) || (UDP_MINPORT > UDP_MAXPORT)
#error "bad UDP_[MIN|MAX]PORT"
#endif
#if (ICMP_MINID < 0) || (ICMP_MAXID > 65535) || (ICMP_MINID > ICMP_MAXID)
#error "bad ICMP_[MIN|MAX]ID"
#endif

u_int poolmin[PRCNT] = { TCP_MINPORT, UDP_MINPORT, ICMP_MINID };
u_int poolmax[PRCNT] = { TCP_MAXPORT, UDP_MAXPORT, ICMP_MAXID };

struct pool {				/* IPv4 addresses for NAT */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	u_char addr[4];
	u_short minport[PRCNT];		/* min ports */
	u_short maxport[PRCNT];		/* max ports */
	u_short natcnt[PRCNT];		/* inuse dynamic NAT entry counters */
	u_char *freebm[PRCNT];		/* free port bit maps */
	ISC_TAILQ_HEAD(, held) helds[PRCNT]; /* on hold NAT tailq */
};

struct pool **pools;		/* NATted source addresses */
u_int poolcnt;			/* NATted source address count */

#define FIRSTGEN	1024

u_int sesgen, curgen, lastgen = FIRSTGEN;

#ifndef TCPBUCKSZ
#define TCPBUCKSZ	10
#endif
#if ((TCPBUCKSZ <= 0) || (TCPBUCKSZ > 255))
#error bad TCPBUCKSZ
#endif
#ifndef UDPBUCKSZ
#define UDPBUCKSZ	8
#endif
#if ((UDPBUCKSZ <= 0) || (UDPBUCKSZ > 255))
#error bad UDPBUCKSZ
#endif
#ifndef ICMPBUCKSZ
#define ICMPBUCKSZ	3
#endif
#if ((ICMPBUCKSZ <= 0) || (ICMPBUCKSZ > 255))
#error bad ICMPBUCKSZ
#endif

u_char bucksize[PRCNT] = { TCPBUCKSZ, UDPBUCKSZ, ICMPBUCKSZ };

#define ALL_DST			1
#define PRR_NULL		2
#define MATCH_PORT		4
#define MATCH_ICMP		8
#define MATCH_ANY		12
#define FTP_DATA		16
#define ON_HOLD			32
#define ALL_FLAGS		31

#ifndef TCP_LIFETIME
#define TCP_LIFETIME		600
#endif
#if ((TCP_LIFETIME <= 0) || (TCP_LIFETIME > 36000))
#error bad TCP_LIFETIME
#endif
#ifndef CLOSED_TCP_LIFETIME
#define CLOSED_TCP_LIFETIME	120
#endif
#if ((CLOSED_TCP_LIFETIME <= 0) || (CLOSED_TCP_LIFETIME > 36000))
#error bad CLOSED_TCP_LIFETIME
#endif
#ifndef UDP_LIFETIME
#define UDP_LIFETIME		300
#endif
#if ((UDP_LIFETIME <= 0) || (UDP_LIFETIME > 36000))
#error bad UDP_LIFETIME
#endif
#ifndef ICMP_LIFETIME
#define ICMP_LIFETIME		30
#endif
#if ((ICMP_LIFETIME <= 0) || (ICMP_LIFETIME > 36000))
#error bad ICMP_LIFETIME
#endif
#ifndef RETRANS_LIFETIME
#define RETRANS_LIFETIME	10
#endif
#if ((RETRANS_LIFETIME <= 0) || (RETRANS_LIFETIME > 36000))
#error bad RETRANS_LIFETIME
#endif

int nat_lifetime[5] = {
	TCP_LIFETIME, CLOSED_TCP_LIFETIME, UDP_LIFETIME,
	ICMP_LIFETIME, RETRANS_LIFETIME };

#ifndef HOLD_LIFETIME
#define HOLD_LIFETIME		120
#endif
#if ((HOLD_LIFETIME < 0) || (HOLD_LIFETIME > 600))
#error bad HOLD_LIFETIME
#endif

u_int hold_lifetime = HOLD_LIFETIME;

#define TCP_DEFAULT		0
#define TCP_ACKED		1
#define TCP_CLOSED_IN		2
#define TCP_CLOSED_OUT		4
#define TCP_CLOSED_BOTH		6

#define RB_BLACK	0
#define RB_RED		1

struct nat {				/* NAT entry */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	struct nat *left;		/* NAT red-black tree */
	struct nat *right;
	struct nat *parent;
	struct nat *tleft;		/* per tunnel splay tree */
	struct nat *tright;
	ISC_LIST_HEAD(, nat) xlist;	/* FTP ALG chain */
	ISC_LIST_ENTRY(nat) xchain;
	ISC_LIST_ENTRY(nat) gchain;	/* global chain */
	struct tunnel *tunnel;		/* pointer to tunnel */
	u_int generation;		/* generation */
	time_t timeout;			/* timeout date (0 == infinity) */
	u_int lifetime;			/* extra lifetime on match */
	u_int heap_index;		/* index in heap */
					/* from tunnel to Internet */
	u_char src[4];			/* (original) source address */
	u_char nsrc[4];			/* (natted) source address */
	u_char dst[4];			/* destination address */
	u_char sport[2];		/* (original) source port */
	u_char nport[2];		/* (natted) source port */
	u_char dport[2];		/* destination port */
	u_char proto;			/* protocol TCP|UDP|ICMP */
	u_char flags;			/* flags */
	u_short hash;			/* last hash */
	u_char tcpst;			/* TCP state */
	u_char color;			/* RB_BLACK | RB_RED */
	ISC_SLIST_HEAD(, ftpseq) ftpseq; /* FTP TCP sequence patch records */
};
struct nat *nat_tree[PRCNT];		/* red-black tree roots */
u_int nat_heap_size;			/* current heap size */
u_int nat_heap_last;			/* heap last index */
struct nat **nat_heap;			/* heap array of NAT entry pointers */
ISC_LIST_HEAD(, nat) confnats;		/* global list of static NAT entries */

u_int natcntt, natcntu, natcnto, snatcnt, prrcnt;	/* global counters */

struct ftpseq {				/* FTP TCP sequence patch record */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	ISC_SLIST_ENTRY(ftpseq) chain;	/* (short) chaining */
	uint32_t oldseq;		/* sequence before the record */
	uint32_t newseq;		/* sequence after the record */
	int delta;			/* sequence delta */
};

/* overlay of the NAT entry (should be a realloc() with a smaller size
 * but in this case the pointer is not changed...) */

struct held {				/* on hold NAT entry */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	ISC_TAILQ_ENTRY(held) chain;	/* chaining */
	struct held *__fill[9];
	u_int __fill0;
	time_t timeout;			/* timeout date (0 == infinity) */
	u_int __fill1[2];
	u_char __fill2[14];
	u_char nport[2];		/* (natted) source port */
	u_char __fill3[3];
	u_char flags;			/* flags */
};

#ifndef TCP_MAXTNATCNT
#define TCP_MAXTNATCNT	2000		/* maximum count of NAT entries */
#endif
#if (TCP_MAXTNATCNT <= 0) || (TCP_MAXTNATCNT > 65535)
#error "bad TCP_MAXTNATCNT value"
#endif
#ifndef UDP_MAXTNATCNT
#define UDP_MAXTNATCNT	200		/* maximum count of NAT entries */
#endif
#if (UDP_MAXTNATCNT <= 0) || (UDP_MAXTNATCNT > 65535)
#error "bad UDP_MAXTNATCNT value"
#endif
#ifndef ICMP_MAXTNATCNT
#define ICMP_MAXTNATCNT	50		/* maximum count of NAT entries */
#endif
#if (ICMP_MAXTNATCNT <= 0) || (ICMP_MAXTNATCNT > 65535)
#error "bad ICMP_MAXTNATCNT value"
#endif
u_short maxtnatcnt[PRCNT] =
	{ TCP_MAXTNATCNT, UDP_MAXTNATCNT, ICMP_MAXTNATCNT };

#ifndef TCP_MAXTNATRT
#define TCP_MAXTNATRT	50		/* maximum rate of NAT creation */
#endif
#if (TCP_MAXTNATRT <= 0) || (TCP_MAXTNATRT > 255)
#error "bad TCP_MAXTNATRT value"
#endif
#ifndef UDP_MAXTNATRT
#define UDP_MAXTNATRT	20		/* maximum rate of NAT creation */
#endif
#if (UDP_MAXTNATRT <= 0) || (UDP_MAXTNATRT > 255)
#error "bad UDP_MAXTNATRT value"
#endif
#ifndef ICMP_MAXTNATRT
#define ICMP_MAXTNATRT	5		/* maximum rate of NAT creation */
#endif
#if (ICMP_MAXTNATRT <= 0) || (ICMP_MAXTNATRT > 255)
#error "bad ICMP_MAXTNATRT value"
#endif
u_short maxtnatrt[PRCNT] = { TCP_MAXTNATRT, UDP_MAXTNATRT, ICMP_MAXTNATRT };

#define MAXTUNBIT	128		/* 16*8 bits of key */
#define TUNDEFMTU	1500		/* default MTU */
#define TUNMINMTU	1280		/* minimal MTU */
#define TUNMSSFLG	0x01		/* patch TCP MSS flag */
#define TUNTBDROP	0x02		/* drop too big DF packets */
#define TUNTBICMP	0x04		/* send too big ICMPv4 */
#define TUNDEBUG	0x08		/* debug is enabled */
#define TUNNONAT	0x10		/* no-nat tunnel */
#define TUNGLUE		0x80		/* unused but still present in tree */

struct tunnel {				/* tunnel entry */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	struct tunnel *parent;		/* tunnel tree */
	struct tunnel *left;
	struct tunnel *right;
	union {				/* dependent data */
		struct t_data *_tdata;
		struct nn_data *_nndata;
	} _u;
#define tdata		_u._tdata
#define nndata		_u._nndata
	u_char remote[16];		/* remote IPv6 address */
#define key	remote
	u_char bit;			/* internal node branch bit */
	u_char flags;			/* flags */
	u_char frg6cnt;			/* IPv6 fragment count */
	u_char frg4cnt;			/* IPv4 in fragment count */
	u_short mtu;			/* tunnel MTU */
	u_short hash;			/* last hash */
};
struct tunnel *tunnel_tree;		/* tunnel tree */
struct tunnel *tunnel_debugged;		/* the tunnel under debug */
u_int tuncnt;				/* global counter */

u_short tundefmtu = TUNDEFMTU;		/* tunnel default MTU (configurable) */
int enable_msspatch = 0;		/* whether to patch MSS (def. cfg.) */
int default_toobig = TUNTBICMP;		/* default policy about too big */

struct t_data {				/* standard tunnel dependent part */
	struct nat *_tnat_root[PRCNT];	/* NAT entries */
	u_short _srcidx;		/* index into pools[] */
	u_short _tnatcnt[PRCNT];	/* NAT entry count */
	time_t _lastnat;		/* NAT creation second */
	u_char _tnatrt[PRCNT];		/* NAT creation counter */
	u_char _avail[PRCNT];		/* available port counter */
	u_short *_bucket[PRCNT];	/* port bucket */
#define tnat_root	tdata->_tnat_root
#define srcidx		tdata->_srcidx
#define tnatcnt		tdata->_tnatcnt
#define lastnat		tdata->_lastnat
#define tnatrt		tdata->_tnatrt
#define avail		tdata->_avail
#define bucket		tdata->_bucket
};

struct nn_data {			/* no-nat tunnel dependent part */
	ISC_STAILQ_ENTRY(tunnel) _nchain; /* no-nat chain */
	u_int _ngeneration;		/* generation */
	u_char _nnaddr[4];		/* no-nat prefix */
	u_short _nnplen;		/* no-nat prefix length */
#define nchain		nndata->_nchain
#define ngeneration	nndata->_ngeneration
#define nnaddr		nndata->_nnaddr
#define nnplen		nndata->_nnplen
};
ISC_STAILQ_HEAD(, tunnel) nonats;	/* no-nat head */

struct acl6 {
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	ISC_STAILQ_ENTRY(acl6) chain;	/* chain */
	u_char addr[16];		/* prefix */
	u_char mask[16];		/* mask */
};
ISC_STAILQ_HEAD(, acl6) acl6s;		/* acl6 stailq */
int acl6(u_char *src);

struct acl4 {				/* aka private */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	ISC_STAILQ_ENTRY(acl4) chain;	/* chain */
	u_char addr[4];			/* prefix */
	u_char mask[4];			/* mask */
};
ISC_STAILQ_HEAD(, acl4) acl4s;		/* acl4 (aka private) stailq */
int acl4(u_char *src);

#define MAXFRAGHASH	256		/* max v4 fragment hash table size */
#define MINFRAGHASH	64		/* min v4 fragment hash table size */

struct frag **fraghash;			/* v4 fragment hash table */
u_int fraghashsz;
uint32_t fraghashrnd;
uint64_t tfhlookups, tfhhits;		/* total lookups/hits counters */
uint64_t pfhlookups, pfhhits;		/* period lookups/hits counters */

#define MAXNATHASH	65536		/* max NAT hash table size */
#define MINNATHASH	1024		/* min NAT hash table size */

struct nat **nathash;			/* NAT hash table */
u_int nathashsz;
uint32_t nathashrnd;
uint64_t tnhlookups, tnhhits;		/* total lookups/hits counters */
uint64_t pnhlookups, pnhhits;		/* period lookups/hits counters */

#define MAXTUNHASH	16384		/* max tunnel hash table size */
#define MINTUNHASH	16		/* min tunnel hash table size */

struct tunnel **tunhash;		/* tunnel hash table */
u_int tunhashsz;
uint32_t tunhashrnd;
uint64_t tthlookups, tthhits;		/* total lookups/hits counters */
uint64_t pthlookups, pthhits;		/* period lookups/hits counters */

#ifndef AFTRPORT
#define AFTRPORT	1015		/* 0xA = 10, 0xF = 15 */
#endif
int aftrport = AFTRPORT;

struct sess {				/* control channel session */
#ifdef SIGNSHDR
	isc_magic_t magic;
#endif
	ISC_LIST_ENTRY(sess) chain;	/* chaining */
	ISC_LIST_HEAD(, nat) snats;	/* dependent static NAT entries */
	struct cctype *sstype;		/* control channel type */
	char *name;			/* for management */
	u_int generation;		/* session generation */
	int fd;				/* file descriptor (for select) */
	FILE *ssout, *sserr, *ssnot;	/* streams */
	size_t cpos;			/* control buffer position */
	u_char section;			/* section mask */
	u_char locked;			/* locked mask */
	char cbuf[600];			/* control buffer */
	int guard;			/* guard/unused */
};
ISC_LIST_HEAD(, sess) sslist;		/* active sessions */
ISC_LIST_HEAD(, sess) orphans;		/* for garbage collection */

struct cctype {				/* control channel type */
	const char *name;
	struct sess *(*ccopen)(void);	/* open method */
	int (*ccclose)(struct sess *ss); /* close method */
};

struct sess *stdio_open(void);
struct sess *unix_open(void);
struct sess *tcp4_open(void);
struct sess *tcp6_open(void);
int stdio_close(struct sess *ss);
int unix_close(struct sess *ss);
int tcp4_close(struct sess *ss);
int tcp6_close(struct sess *ss);

struct cctype ccstdio = { "stdio", &stdio_open, &stdio_close };
struct cctype ccunix = { "unix", &unix_open, &unix_close };
struct cctype cctcp4 = { "tcp4", &tcp4_open, &tcp4_close };
struct cctype cctcp6 = { "tcp6", &tcp6_open, &tcp6_close };
int unix_fd = -1;
int tcp4_fd = -1;
int tcp6_fd = -1;

void fork_child(struct sess *ss);
int loading = 0;
int load_file(struct sess *ss, char *filename);
int reload_conf(struct sess *ss);
FILE *reload_stream = NULL;
struct sess *reload_session = NULL;
int reload_ln;
u_int reload_savedgen;
u_char reload_savedsec, reload_savedloc;
int reloading = 0;
int checkconf = 0;
struct nat *bt_ptr;
int needbt;
struct nat *gc_ptr;
int needgc;

struct cmd {
	char *name;
	u_char len;			/* could be populated at startup */
	u_char required_args;
	u_char section;			/* 1 << section_number */
	int (*func)(struct sess *ss, char *line, char *usage);
	char *usage;
};

int cmd_abort(struct sess *ss, char *tok, char *usage);
int cmd_acl6(struct sess *ss, char *tok, char *usage);
int cmd_address(struct sess *ss, char *tok, char *usage);
int cmd_autotunnel(struct sess *ss, char *tok, char *usage);
int cmd_bucket(struct sess *ss, char *tok, char *usage);
int cmd_debug(struct sess *ss, char *tok, char *usage);
int cmd_decay(struct sess *ss, char *tok, char *usage);
int cmd_default(struct sess *ss, char *tok, char *usage);
int cmd_defmss(struct sess *ss, char *tok, char *usage);
int cmd_defmtu(struct sess *ss, char *tok, char *usage);
int cmd_deftoobig(struct sess *ss, char *tok, char *usage);
int cmd_delete(struct sess *ss, char *tok, char *usage);
int cmd_echo(struct sess *ss, char *tok, char *usage);
int cmd_eqfrag(struct sess *ss, char *tok, char *usage);
int cmd_fork(struct sess *ss, char *tok, char *usage);
int cmd_help(struct sess *ss, char *tok, char *usage);
int cmd_kill(struct sess *ss, char *tok, char *usage);
int cmd_list(struct sess *ss, char *tok, char *usage);
int cmd_load(struct sess *ss, char *tok, char *usage);
int cmd_mss(struct sess *ss, char *tok, char *usage);
int cmd_mtu(struct sess *ss, char *tok, char *usage);
int cmd_nat(struct sess *ss, char *tok, char *usage);
int cmd_nonat(struct sess *ss, char *tok, char *usage);
int cmd_noop(struct sess *ss, char *tok, char *usage);
int cmd_pool(struct sess *ss, char *tok, char *usage);
int cmd_prr(struct sess *ss, char *tok, char *usage);
int cmd_quantum(struct sess *ss, char *tok, char *usage);
int cmd_quit(struct sess *ss, char *tok, char *usage);
int cmd_reboot(struct sess *ss, char *tok, char *usage);
int cmd_reload(struct sess *ss, char *tok, char *usage);
int cmd_session(struct sess *ss, char *tok, char *usage);
int cmd_show(struct sess *ss, char *tok, char *usage);
int cmd_toobig(struct sess *ss, char *tok, char *usage);
int cmd_try(struct sess *ss, char *tok, char *usage);
int cmd_tunnel(struct sess *ss, char *tok, char *usage);

struct cmd cmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "abort",	 5, 0, 8, cmd_abort,
	  "" },
	{ "acl6",	 4, 1, 6, cmd_acl6,
	  "<IPv6>/<prefix_length>" },
	{ "address",	 7, 1, 2, cmd_address,
	  "endpoint <IPv6>|icmp <IPv4>" },
	{ "autotunnel", 10, 1, 1, cmd_autotunnel,
	  "on|off" },
	{ "bucket",	 6, 1, 1, cmd_bucket,
	  "tcp|udp|icmp size <size>" },
	{ "debug",	 5, 1, 12, cmd_debug,
	  "set|enable|disable|dropped|fragment|hash|nat|"
	  "nonat|pool|session|stat|tunnel" },
	{ "decay",	 5, 1, 1, cmd_decay,
	  "1|5|15 <decay>" },
	{ "default",	 7, 1, 1, cmd_default,
	  "fragment|hold|nat|pool|private|quantum|tunnel" },
	{ "defmss",	 6, 1, 1, cmd_defmss,
	  "on|off" },
	{ "defmtu",	 6, 1, 1, cmd_defmtu,
	  "<mtu>" },
	{ "deftoobig",	 9, 1, 1, cmd_deftoobig,
	  "on|off|strict" },
	{ "delete",	 6, 1, 15, cmd_delete,
	  "acl6|nat|nonat|private|prr|tunnel" },
	{ "echo",	 4, 1, 8, cmd_echo,
	  "<xxx>" },
	{ "eqfrag",	 6, 1, 1, cmd_eqfrag,
	  "on|off" },
	{ "fork",	 4, 0, 8, cmd_fork,
	  "" },
	{ "help",	 4, 0, 8, cmd_help,
	  "[all]" },
	{ "kill",	 4, 0, 8, cmd_kill,
	  "" },
	{ "list",	 4, 1, 9, cmd_list,
	  "acl6|default|nat|nonat|pool|tunnel" },
	{ "load",	 4, 1, 8, cmd_load,
	  "<file>" },
	{ "mss",	 3, 1, 12, cmd_mss,
	  "<IPv6> on|off" },
	{ "mtu",	 3, 1, 12, cmd_mtu,
	  "<IPv6> <mtu>" },
	{ "nat",	 3, 1, 4, cmd_nat,
	  "<IPv6> tcp|udp <IPv4_src> <port_src> <IPv4_new> <port_new>" },
	{ "nonat",	 5, 1, 4, cmd_nonat,
	  "<IPv6> <IPv4>/<prefix_length>" },
	{ "noop",	 4, 0, 8, cmd_noop,
	  "" },
	{ "pool",	 4, 1, 2, cmd_pool,
	  "<IPv4> [tcp|udp|echo <min>-<max>]" },
	{ "prr",	 3, 1, 4, cmd_prr,
	  "<IPv6> tcp|udp <IPv4> <port>" },
	{ "quantum",	 7, 1, 1, cmd_quantum,
	  "<quantum>" },
	{ "quit",	 4, 0, 8, cmd_quit,
	  "" },
	{ "reboot",	 6, 0, 8, cmd_reboot,
	  "" },
	{ "reload",	 6, 0, 8, cmd_reload,
	  "" },
	{ "session",	 7, 1, 8, cmd_session,
	  "close|config|log|name|notify" },
	{ "show",	 4, 1, 8, cmd_show,
	  "dropped|stat" },
	{ "toobig",	 6, 1, 12, cmd_toobig,
	  "<IPv6> on|off|strict" },
	{ "try",	 3, 1, 4, cmd_try,
	  "tunnel <IPv6> [<IPv4>]| "
	  "nat <IPv6> tcp|udp <IPv4_src> <port_src> <IPv4_new> <port_new>" },
	{ "tunnel",	 6, 1, 4, cmd_tunnel,
	  "<IPv6> [<IPv4>]" },
	{ NULL,		 0, 0, 0, NULL,
	  "" }
};

int cmd_debug_check(struct sess *ss, char *tok, char *usage);
int cmd_debug_disable(struct sess *ss, char *tok, char *usage);
int cmd_debug_dropped(struct sess *ss, char *tok, char *usage);
int cmd_debug_enable(struct sess *ss, char *tok, char *usage);
int cmd_debug_fragment(struct sess *ss, char *tok, char *usage);
int cmd_debug_hash(struct sess *ss, char *tok, char *usage);
int cmd_debug_help(struct sess *ss, char *tok, char *usage);
int cmd_debug_nat(struct sess *ss, char *tok, char *usage);
int cmd_debug_nonat(struct sess *ss, char *tok, char *usage);
int cmd_debug_pool(struct sess *ss, char *tok, char *usage);
int cmd_debug_session(struct sess *ss, char *tok, char *usage);
int cmd_debug_set(struct sess *ss, char *tok, char *usage);
int cmd_debug_stat(struct sess *ss, char *tok, char *usage);
int cmd_debug_tunnel(struct sess *ss, char *tok, char *usage);

struct cmd debugcmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "check",	5, 0, 8, cmd_debug_check,
	  "[nat|nonat|pool|session|tunnel]" },
	{ "disable",	7, 0, 8,  cmd_debug_disable,
	  "[clear]" },
	{ "dropped",	7, 0, 8,  cmd_debug_dropped,
	  "" },
	{ "enable",	6, 1, 12, cmd_debug_enable,
	  "<addr>" },
	{ "fragment",	8, 1, 8,  cmd_debug_fragment,
	  "IPv6|in|out|<addr>" },
	{ "hash",	4, 0, 8,  cmd_debug_hash,
	  "" },
	{ "help",	4, 0, 8,  cmd_debug_help,
	  "" },
	{ "nat",	3, 0, 8,  cmd_debug_nat,
	  "[<addr>]" },
	{ "nonat",	5, 0, 8,  cmd_debug_nonat,
	  "" },
	{ "pool",	4, 0, 8,  cmd_debug_pool,
	  "" },
	{ "session",	7, 0, 8,  cmd_debug_session,
	  "" },
	{ "set",	3, 0, 12, cmd_debug_set,
	  "[<level>]" },
	{ "stat",	4, 0, 8,  cmd_debug_stat,
	  "" },
	{ "tunnel",	6, 0, 8,  cmd_debug_tunnel,
	  "[<IPv6>]" },
	{ NULL,		0, 0, 0,  NULL,
	  "" }
};

int cmd_default_fragment(struct sess *ss, char *tok, char *usage);
int cmd_default_help(struct sess *ss, char *tok, char *usage);
int cmd_default_hold(struct sess *ss, char *tok, char *usage);
int cmd_default_nat(struct sess *ss, char *tok, char *usage);
int cmd_default_pool(struct sess *ss, char *tok, char *usage);
int cmd_default_private(struct sess *ss, char *tok, char *usage);
int cmd_default_tunnel(struct sess *ss, char *tok, char *usage);

struct cmd defaultcmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "fragment",	8, 1, 1, cmd_default_fragment,
	  "equal on|of | ipv6|in|out maxcount <cnt> | lifetime <lft>" },
	{ "help",	4, 0, 8, cmd_default_help,
	  "" },
	{ "hold",	4, 1, 1, cmd_default_hold,
	  "lifetime <lifetime>" },
	{ "nat",	3, 1, 1, cmd_default_nat,
	  "lifetime tcp|closed|udp|icmp|retrans" },
	{ "pool",	4, 1, 1, cmd_default_pool,
	  "tcp|udp|echo <min>-<max>" },
	{ "private",	7, 1, 1, cmd_default_private,
	  "<IPv4>/<prefix_length>" },
	{ "tunnel",	6, 1, 1, cmd_default_tunnel,
	  "auto|mss|mtu|toobig|fragment|nat" },
	{ NULL,		0, 0, 0,  NULL,
	  "" }
};

int cmd_delete_acl6(struct sess *ss, char *tok, char *usage);
int cmd_delete_help(struct sess *ss, char *tok, char *usage);
int cmd_delete_nat(struct sess *ss, char *tok, char *usage);
int cmd_delete_nonat(struct sess *ss, char *tok, char *usage);
int cmd_delete_private(struct sess *ss, char *tok, char *usage);
int cmd_delete_prr(struct sess *ss, char *tok, char *usage);
int cmd_delete_tunnel(struct sess *ss, char *tok, char *usage);

struct cmd deletecmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "acl6",	4, 1, 6, cmd_delete_acl6,
	  "<IPv6>" },
	{ "help",	4, 0, 8, cmd_delete_help,
	  "" },
	{ "nat",	3, 1, 4, cmd_delete_nat,
	  "<IPv6> tcp|udp <IPv4> <port>" },
	{ "nonat",	5, 1, 4, cmd_delete_nonat,
	  "<IPv6>" },
	{ "private",	7, 1, 1, cmd_delete_private,
	  "<IPv4>" },
	{ "prr",	3, 1, 4, cmd_delete_prr,
	  "<IPv6> tcp|udp <IPv4> <port>" },
	{ "tunnel",	6, 1, 4, cmd_delete_tunnel,
	  "<IPv6>" },
	{ NULL,		0, 0, 0, NULL,
	  "" }
};

int cmd_list_acl6(struct sess *ss, char *tok, char *usage);
int cmd_list_default(struct sess *ss, char *tok, char *usage);
int cmd_list_help(struct sess *ss, char *tok, char *usage);
int cmd_list_nat(struct sess *ss, char *tok, char *usage);
int cmd_list_nonat(struct sess *ss, char *tok, char *usage);
int cmd_list_pool(struct sess *ss, char *tok, char *usage);
int cmd_list_session(struct sess *ss, char *tok, char *usage);
int cmd_list_tunnel(struct sess *ss, char *tok, char *usage);

struct cmd listcmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "acl6",	4, 0, 8, cmd_list_acl6,
	  "" },
	{ "default",	7, 0, 9, cmd_list_default,
	  "" },
	{ "help",	4, 0, 8, cmd_list_help,
	  "" },
	{ "nat",	3, 0, 8, cmd_list_nat,
	  "[conf|static|prr|dynamic|all|global]" },
	{ "nonat",	5, 0, 8, cmd_list_nonat,
	  "" },
	{ "pool",	4, 0, 8, cmd_list_pool,
	  "" },
	{ "session",    7, 0, 8, cmd_list_session,
	  "[<name>|<generation>]" },
	{ "tunnel",	6, 0, 8, cmd_list_tunnel,
	  "" },
	{ NULL,		0, 0, 0, NULL,
	  "" }
};

int cmd_session_close(struct sess *ss, char *tok, char *usage);
int cmd_session_config(struct sess *ss, char *tok, char *usage);
int cmd_session_help(struct sess *ss, char *tok, char *usage);
int cmd_session_log(struct sess *ss, char *tok, char *usage);
int cmd_session_name(struct sess *ss, char *tok, char *usage);
int cmd_session_notify(struct sess *ss, char *tok, char *usage);

struct cmd sessioncmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "close",    5, 0, 8, cmd_session_close,  "[<name>|<generation>]" },
	{ "config",   6, 1, 8, cmd_session_config, "on|off" },
	{ "help",     4, 0, 8, cmd_session_help,   "" },
	{ "list",     4, 0, 8, cmd_list_session,   "[<name>|<generation>]" },
	{ "log",      3, 1, 8, cmd_session_log,	   "on|off" },
	{ "name",     4, 0, 8, cmd_session_name,   "[<name>]" },
	{ "notify",   6, 0, 8, cmd_session_notify, "on|off" },
	{ "quit",     4, 0, 8, cmd_session_close,  "" },
	{ NULL,	      0, 0, 0, NULL,	       	   "" }
};

int cmd_show_help(struct sess *ss, char *tok, char *usage);

struct cmd showcmd[] = {
	/* MUST REMAIN IN ALPHABETICAL ORDER */
	{ "dropped",	7, 0, 8, cmd_debug_dropped, "" },
	{ "help",	4, 0, 8, cmd_show_help,    "" },
	{ "stat",	4, 0, 8, cmd_debug_stat,    "" },
	{ NULL,		0, 0, 0, NULL,		    "" }
};

int cmd_sub_help(struct sess *ss, char *prefix, struct cmd *cmds);

const u_char mask4[33][4] = {
	{ 0x00, 0x00, 0x00, 0x00 },
	{ 0x80, 0x00, 0x00, 0x00 },
	{ 0xc0, 0x00, 0x00, 0x00 },
	{ 0xe0, 0x00, 0x00, 0x00 },
	{ 0xf0, 0x00, 0x00, 0x00 },
	{ 0xf8, 0x00, 0x00, 0x00 },
	{ 0xfc, 0x00, 0x00, 0x00 },
	{ 0xfe, 0x00, 0x00, 0x00 },
	{ 0xff, 0x00, 0x00, 0x00 },
	{ 0xff, 0x80, 0x00, 0x00 },
	{ 0xff, 0xc0, 0x00, 0x00 },
	{ 0xff, 0xe0, 0x00, 0x00 },
	{ 0xff, 0xf0, 0x00, 0x00 },
	{ 0xff, 0xf8, 0x00, 0x00 },
	{ 0xff, 0xfc, 0x00, 0x00 },
	{ 0xff, 0xfe, 0x00, 0x00 },
	{ 0xff, 0xff, 0x00, 0x00 },
	{ 0xff, 0xff, 0x80, 0x00 },
	{ 0xff, 0xff, 0xc0, 0x00 },
	{ 0xff, 0xff, 0xe0, 0x00 },
	{ 0xff, 0xff, 0xf0, 0x00 },
	{ 0xff, 0xff, 0xf8, 0x00 },
	{ 0xff, 0xff, 0xfc, 0x00 },
	{ 0xff, 0xff, 0xfe, 0x00 },
	{ 0xff, 0xff, 0xff, 0x00 },
	{ 0xff, 0xff, 0xff, 0x80 },
	{ 0xff, 0xff, 0xff, 0xc0 },
	{ 0xff, 0xff, 0xff, 0xe0 },
	{ 0xff, 0xff, 0xff, 0xf0 },
	{ 0xff, 0xff, 0xff, 0xf8 },
	{ 0xff, 0xff, 0xff, 0xfc },
	{ 0xff, 0xff, 0xff, 0xfe },
	{ 0xff, 0xff, 0xff, 0xff }
};

const u_char mask6[129][16] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8 },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe },
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

/*
 * Utils
 */

/* logging, mainly for debug */

void
logdebug(int loglvl, const char *msg, ...)
{
	if (loglvl <= debuglevel) {
		struct sess *ss;
		va_list va;

		va_start(va, msg);
		ISC_LIST_FOREACH(ss, &sslist, chain)
			if (ss->sserr != NULL) {
				va_list ca;

				va_copy(ca, va);
				fputs("LOG: ", ss->sserr);
				vfprintf(ss->sserr, msg, ca);
				putc('\n', ss->sserr);
				va_end(ca);
			}
		vsyslog(LOG_DEBUG, msg, va);
		va_end(va);
	}
}

/* replacements for 'fprintf(stderr, ...\n)' */

void
logcrit(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		va_list ca;

		va_copy(ca, va);
		if (ss->sserr != NULL)
			vfprintf(ss->sserr, msg, ca);
		else if (ss->ssout != NULL)
			vfprintf(ss->ssout, msg, ca);
		va_end(ca);
	}
	vsyslog(LOG_CRIT, msg, va);
	va_end(va);
}

void
logerr(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->sserr != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->sserr, msg, ca);
			va_end(ca);
		}
	vsyslog(LOG_ERR, msg, va);
	va_end(va);
}

void
sslogdebug0(struct sess *ss0, char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	if ((ss0 != NULL) && (ss0->fd != -1)) {
		va_list ca;

		va_copy(ca, va);
		vfprintf(ss0->ssout, msg, va);
		putc('\n', ss0->ssout);
		va_end(ca);
	}
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if ((ss != ss0) && (ss->sserr != NULL)) {
			va_list ca;

			va_copy(ca, va);
			fputs("LOG: ", ss->sserr);
			vfprintf(ss->sserr, msg, ca);
			putc('\n', ss->sserr);
			va_end(ca);
		}
	vsyslog(LOG_DEBUG, msg, va);
	va_end(va);
}

void
sslogerr(struct sess *ss0, char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->sserr != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->sserr, msg, ca);
			va_end(ca);
		}
	if ((ss0 != NULL) && (ss0->fd != -1) && (ss0->sserr == NULL)) {
		va_list ca;

		va_copy(ca, va);
		vfprintf(ss0->ssout, msg, va);
		va_end(ca);
	}
	vsyslog(LOG_ERR, msg, va);
	va_end(va);
}

void
logwarning(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->sserr != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->sserr, msg, ca);
			va_end(ca);
		}
	vsyslog(LOG_WARNING, msg, va);
	va_end(va);
}

void
loginfo(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->sserr != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->sserr, msg, ca);
			va_end(ca);
		}
	vsyslog(LOG_INFO, msg, va);
	va_end(va);
}

/* convert to string (print helpers) */

char *
addr2str(int family, u_char *addr)
{
	static char addrbuf[8][NI_MAXHOST]; /* XXX ugly thread-unsafe hack */
	static int round = 0;
	char *cp;

	round = (round + 1) & 7;
	cp = addrbuf[round];

	/* XXX: assume this succeeds */
	inet_ntop(family, addr, cp, NI_MAXHOST);

	return (cp);
}

char *
proto2str(u_int proto)
{
	static char buf[16];

	/* sort by likely frequency, not by absolute value */
	switch (proto) {
	case IPTCP:
		return "tcp";
	case IPUDP:
		return "udp";
	case IPICMP:
		return "icmp";
	default:
		sprintf(buf, "%u", proto);
		return buf;
	}
}

char *
toobig2str(struct tunnel *t)
{
	switch (t->flags & (TUNTBDROP | TUNTBICMP)) {
	case 0:
		return "off";
	case TUNTBICMP:
		return "on";
	case (TUNTBDROP | TUNTBICMP):
		return "strict";
	default:
		return "drop-only";
	}
}

/* Print tunnel interface/device I/O time stamps (tcpdump -tt format) */

void
print_iots(char *way, ssize_t cc)
{
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	loginfo("%u.%06u %s %u\n",
		(unsigned) tv.tv_sec, (unsigned) tv.tv_usec,
		way, (unsigned) cc);
}

/* For FreeBSD compatibility */

ssize_t
tun_read(void *b, size_t c)
{
#ifndef __linux__
	struct iovec iov[2];
	uint32_t ifh;
	ssize_t cc;

	ifh = 0;
	iov[0].iov_base = &ifh;
	iov[0].iov_len = sizeof(ifh);
	iov[1].iov_base = b;
	iov[1].iov_len = c;
	cc = readv(tunfd, iov, 2);
	if (cc < 0) {
		if (errno == EWOULDBLOCK)
			return -EWOULDBLOCK;
		return cc;
	}
	if ((size_t) cc < sizeof(ifh))
		return 0;
	cc -= sizeof(ifh);
	if (debuglevel > 10)
		print_iots("in", cc);
	return cc;
#else
#ifdef USE_TUN_PI
	struct iovec iov[2];
	struct tun_pi pi;
	ssize_t cc;

	pi.flags = 0;
	pi.proto = 0;
	iov[0].iov_base = &pi;
	iov[0].iov_len = sizeof(pi);
	iov[1].iov_base = b;
	iov[1].iov_len = c;
	cc = readv(tunfd, iov, 2);
	if (cc < 0) {
		if (errno == EAGAIN)
			return -EWOULDBLOCK;
		return cc;
	}
	if ((size_t) cc < sizeof(pi))
		return 0;
	cc -= sizeof(pi);
	if (debuglevel > 10)
		print_iots("in", cc);
	return cc;
#else
	ssize_t cc;

	cc = read(tunfd, b, c);
	if ((cc < 0) && (errno == EAGAIN))
		return -EWOULDBLOCK;
	if ((cc > 0) && (debuglevel > 10))
		print_iots("in", cc);
	return cc;
#endif
#endif
}

ssize_t
tun_write(int af, void *b, size_t c)
{
#ifndef __linux__
	struct iovec iov[2];
	uint32_t ifh;
	ssize_t cc;

	ifh = htonl((uint32_t) af);
	iov[0].iov_base = &ifh;
	iov[0].iov_len = sizeof(ifh);
	iov[1].iov_base = b;
	iov[1].iov_len = c;
	cc = writev(tunfd, iov, 2);
	if (cc < 0) {
		if (errno == EWOULDBLOCK)
			return 0;
		return cc;
	}
	if ((size_t) cc < sizeof(ifh))
		return 0;
	cc -= sizeof(ifh);
	if (debuglevel > 10)
		print_iots("out", cc);
	return cc;
#else
#ifdef USE_TUN_PI
	struct iovec iov[2];
	struct tun_pi pi;
	ssize_t cc;

	pi.flags = 0;
	if (af == AF_INET6)
		pi.proto = htons(ETH_P_IPV6);
	else
		pi.proto = htons(ETH_P_IP);
	iov[0].iov_base = &pi;
	iov[0].iov_len = sizeof(pi);
	iov[1].iov_base = b;
	iov[1].iov_len = c;
	cc = writev(tunfd, iov, 2);
	if (cc < 0) {
		if (errno == EAGAIN)
			return 0;
		return cc;
	}
	if ((size_t) cc < sizeof(pi))
		return 0;
	cc -= sizeof(pi);
	if (debuglevel > 10)
		print_iots("out", cc);
	return cc;
#else
	ssize_t cc;

	(void) af;
	cc = write(tunfd, b, c);
	if ((cc < 0) && (errno == EAGAIN))
		return 0;
	if ((cc > 0) && (debuglevel > 10))
		print_iots("out", cc);
        return cc;
#endif
#endif
}

/* Open tun interface/device (OS dependent) */

int
tun_open(void)
{
	int fd = -1;
	int i;

#ifndef __linux__
	if (strcasecmp(aftrdevice, "auto") == 0) {
		for (i = 0; i <= 255; i++) {
			snprintf(tunname, sizeof(tunname), "/dev/tun%d", i);
			fd = open(tunname, O_RDWR);
			if (fd >= 0)
				loginfo("using device \"%s\"\n", tunname);
			if ((fd >= 0) || (errno == ENOENT))
				break;
		}
	} else if (isdigit(aftrdevice[0])) {
		i = atoi(aftrdevice);
		snprintf(tunname, sizeof(tunname), "/dev/tun%d", i);
		fd = open(tunname, O_RDWR);
	} else if (aftrdevice[0] == '/') {
		if (strlen(aftrdevice) >= sizeof(tunname)) {
			logcrit("device name \"%s\" too long\n", aftrdevice);
			return -1;
		}
		strcpy(tunname, aftrdevice);
		fd = open(tunname, O_RDWR);
	} else {
		if (strlen(aftrdevice) + 5 >= sizeof(tunname)) {
			logcrit("device name \"%s\" too long\n", aftrdevice);
			return -1;
		}
		sprintf(tunname, "/dev/%s", aftrdevice);
		fd = open(tunname, O_RDWR);
	}
	if (fd >= 0) {
		i = 0;
		ioctl(fd, TUNSLMODE, &i);
		i = 1;
		ioctl(fd, TUNSIFHEAD, &i);
		i = IFF_POINTOPOINT;
		ioctl(fd, TUNSIFMODE, &i);
	} else
		logcrit("open(\"%s\"): %s\n", tunname, strerror(errno));
#else
	struct ifreq ifr;

	if (strlen(aftrdevice) >= sizeof(tunname)) {
		logcrit("device name \"%s\" too long\n", aftrdevice);
		return -1;
	}
	if (strncmp(aftrdevice, "/dev/net/", 9) == 0)
		strcpy(tunname, aftrdevice + 9);
	else if (strncmp(aftrdevice, "/dev/", 5) == 0)
		strcpy(tunname, aftrdevice + 5);
	else if (isdigit(aftrdevice[0])) {
		i = atoi(aftrdevice);
		sprintf(tunname, "tun%d", i);
	} else
		strcpy(tunname, aftrdevice);
	if (strlen(tunname) > IFNAMSIZ)
		logerr("device name will be truncated\n");
		
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		logcrit("open: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tunname, IFNAMSIZ);
#ifdef USE_TUN_PI
	ifr.ifr_flags = IFF_TUN;
#else
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#endif
       
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		logerr("fcntl: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		logcrit("ioctl: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
#ifdef notyet
	ioctl(fd, TUNSETNOCSUM, 1);
#endif
#endif
	return fd;
}

/* Tracing */

void
logtrace(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->sserr != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->sserr, msg, ca);
			va_end(ca);
		}
	vsyslog(LOG_NOTICE, msg, va);
	va_end(va);
}

void
trace_tunnel(struct tunnel *t, char *action)
{
	logtrace("tunnel %s %s\n", action, addr2str(AF_INET6, t->remote));
}

#ifdef TRACE_NAT
void
trace_nat(struct nat *n, char *action)
{
#ifdef NOPRIVACY
	u_int sp, np, dp;

	sp = n->sport[0] << 8;
	sp |= n->sport[1];
	np = n->nport[0] << 8;
	np |= n->nport[1];
	dp = n->dport[0] << 8;
	dp |= n->dport[1];
	logtrace("%ld nat %s %s %s %s %u %s %u %s %u\n",
		 (long) seconds, action,
		 addr2str(AF_INET6, n->tunnel->remote),
		 n->proto == IPTCP ? "tcp" : "udp",
		 addr2str(AF_INET, n->src), sp,
		 addr2str(AF_INET, n->nsrc), np,
		 addr2str(AF_INET, n->dst), dp);
#else
	u_int p;

	p = n->nport[0] << 8;
	p |= n->nport[1];
	logtrace("%ld nat %s %s %s %s %u\n",
		 (long) seconds, action,
		 addr2str(AF_INET6, n->tunnel->remote),
		 n->proto == IPTCP ? "tcp" : "udp",
		 addr2str(AF_INET, n->nsrc), p);
#endif
}		
#endif

void
trace_bucket(struct tunnel *t, int proto)
{
	char buf[1024];
	int cc;
	u_short *b;
	u_char pr, i;
	char *p, *end;

	switch (proto) {
	case IPTCP:
		pr = TCPPR;
		break;
	case IPUDP:
		pr = UDPPR;
		break;
	default:
		return;
	}
	memset(buf, 0, sizeof(buf));
	p = buf;
	end = buf + sizeof(buf);
	cc = snprintf(p, end - p,
		      "%ld bucket %s %s %s",
		      (long) seconds,
		      addr2str(AF_INET6, t->remote),
		      addr2str(AF_INET, pools[t->srcidx]->addr),
		      proto == IPTCP ? "tcp" : "udp");
	p += cc;
	b = t->bucket[pr];
	for (i = 0; i < t->avail[pr]; i++) {
		cc = snprintf(p, end - p, " #%hu", b[i]);
		p += cc;
	}
	logtrace("%s\n", buf);
}		

/*
 * Notify
 */

void
notify(const char *msg, ...)
{
	struct sess *ss;
	va_list va;

	va_start(va, msg);
	ISC_LIST_FOREACH(ss, &sslist, chain)
		if (ss->ssnot != NULL) {
			va_list ca;

			va_copy(ca, va);
			vfprintf(ss->ssnot, msg, ca);
			va_end(ca);
		}
	va_end(va);
}

/*
 * arc4random(), from Open/FreeBSD
 */

struct arc4_stream {
	u_char i;
	u_char j;
	u_char s[256];
} rs;

void
arc4_init(void)
{
	int n;

	for (n = 0; n < 256; n++)
		rs.s[n] = n;
	rs.i = 0;
	rs.j = 0;
}

inline void
arc4_addrandom(u_char *dat, int datlen)
{
	int n;
	u_char si;

	rs.i--;
	for (n = 0; n < 256; n++) {
		rs.i = (rs.i + 1);
		si = rs.s[rs.i];
		rs.j = (rs.j + si + dat[n % datlen]);
		rs.s[rs.i] = rs.s[rs.j];
		rs.s[rs.j] = si;
	}
}

inline u_char
arc4_getbyte(void)
{
	u_char si, sj;

	rs.i = (rs.i + 1);
	si = rs.s[rs.i];
	rs.j = (rs.j + si);
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;

	return (rs.s[(si + sj) & 0xff]);
}

inline u_short
arc4_getshort(void)
{
	u_short val;

	val = arc4_getbyte() << 8;
	val |= arc4_getbyte();

	return (val);
}

inline uint32_t
arc4_getword(void)
{
	uint32_t val;

	val = arc4_getbyte() << 24;
	val |= arc4_getbyte() << 16;
	val |= arc4_getbyte() << 8;
	val |= arc4_getbyte();

	return (val);
}

inline u_short
arc4_getport(u_short minport, u_short maxport)
{
	u_short r = maxport - minport;
	u_short x;

	if (r == 0)
		return minport;
	if (r == 1)
		return minport + (arc4_getbyte() & 1);
	if (r == 65535)
		return arc4_getshort();
	r += 1;
	for (;;) {
		x = arc4_getshort();
		if ((int)x < (65536 - (65536 % r)))
			return minport + (x % r);
	}
}

void
arc4_stir(void)
{
	int fd, n;
	struct {
		struct timeval tv;
		pid_t pid;
		u_char rnd[128 - sizeof(struct timeval) - sizeof(pid_t)];
	} rdat;

	gettimeofday(&rdat.tv, NULL);
	rdat.pid = getpid();
	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd >= 0) {
#if defined(__GNUC__) && (__GNUC__ > 3)
		__builtin_expect(read(fd, rdat.rnd, sizeof(rdat.rnd)),
				 sizeof(rdat.rnd));
#else
		(void) read(fd, rdat.rnd, sizeof(rdat.rnd));
#endif
		(void) close(fd);
	} 
	arc4_addrandom((void *) &rdat, sizeof(rdat));
	for (n = 0; n < 1024; n++)
		(void) arc4_getbyte();
}

/*
 * Data structures
 *	basic
 */

/* Jenkins hash */

#define __jhash_mix(a, b, c) { \
	a -= b; a -= c; a ^= (c >> 13);	\
	b -= c; b -= a; b ^= (a << 8);	\
	c -= a; c -= b; c ^= (b >> 13);	\
	a -= b; a -= c; a ^= (c >> 12);	\
	b -= c; b -= a; b ^= (a << 16);	\
	c -= a; c -= b; c ^= (b >> 5);	\
	a -= b; a -= c; a ^= (c >> 3);	\
	b -= c; b -= a; b ^= (a << 10);	\
	c -= a; c -= b; c ^= (b >> 15);	}

#define JHASH_GOLDEN_RATIO	0x9e3779b9

inline u_short
jhash_frag(void)
{
	uint32_t a, b, c;

	memcpy(&a, buf4 + IPSRC, 4);
	a += JHASH_GOLDEN_RATIO;
	memcpy(&b, buf4 + IPDST, 4);
	b += JHASH_GOLDEN_RATIO;
	memcpy(&c, &buf4[IPID], 2);
	memcpy((u_char *) &c + 2, &buf4[IPID], 2);
	c += fraghashrnd;

	__jhash_mix(a, b, c);

	c = (c >> 16) + (c & 0xffff);
	c &= 0xffff;
	return (u_short) c;
}

inline u_short
jhash_nat(struct nat *n)
{
	uint32_t a, b, c;

	memcpy(&a, n->nsrc, 4);
	a += JHASH_GOLDEN_RATIO;
	memcpy(&b, n->nport, 2);
	memcpy((u_char *) &b + 2, n->nport, 2);
	b += JHASH_GOLDEN_RATIO;
	c = n->proto + nathashrnd;

	__jhash_mix(a, b, c);

	c = (c >> 16) + (c & 0xffff);
	c &= 0xffff;
	return (u_short) c;
}

inline u_short
jhash_tunnel(u_char *addr)
{
	uint32_t a, b, c, k;

	memcpy(&a, addr, 4);
	a += JHASH_GOLDEN_RATIO;
	memcpy(&b, addr + 4, 4);
	b += JHASH_GOLDEN_RATIO;
	memcpy(&c, addr + 8, 4);
	c += tunhashrnd;

	__jhash_mix(a, b, c);

	memcpy(&k, addr + 12, 4);
	a += k;

	__jhash_mix(a, b, c);

	c = (c >> 16) + (c & 0xffff);
	c &= 0xffff;
	return (u_short) c;
}

/* Nat entry compare routines */

int
nat_tree_compare_all(struct nat *n1, struct nat *n2)
{
	if (n1->tunnel != n2->tunnel)
		return 1;
	if (n1->proto != n2->proto)
		return 1;
	if (n1->flags != n2->flags)
		return 1;
	if (n1->src[0] != n2->src[0])
		return 1;
	if (n1->src[1] != n2->src[1])
		return 1;
	if (n1->src[2] != n2->src[2])
		return 1;
	if (n1->src[3] != n2->src[3])
		return 1;
	if (n1->sport[0] != n2->sport[0])
		return 1;
	if (n1->sport[1] != n2->sport[1])
		return 1;
	if (n1->nsrc[0] != n2->nsrc[0])
		return 1;
	if (n1->nsrc[1] != n2->nsrc[1])
		return 1;
	if (n1->nsrc[2] != n2->nsrc[2])
		return 1;
	if (n1->nsrc[3] != n2->nsrc[3])
		return 1;
	if (n1->nport[0] != n2->nport[0])
		return 1;
	if (n1->nport[1] != n2->nport[1])
		return 1;
	if (n1->dst[0] != n2->dst[0])
		return 1;
	if (n1->dst[1] != n2->dst[1])
		return 1;
	if (n1->dst[2] != n2->dst[2])
		return 1;
	if (n1->dst[3] != n2->dst[3])
		return 1;
	if (n1->dport[0] != n2->dport[0])
		return 1;
	if (n1->dport[1] != n2->dport[1])
		return 1;
	return 0;
}

int
nat_tree_compare_abs(struct nat *n1, struct nat *n2)
{
	if (n1->proto != n2->proto)
		return (int)n1->proto - (int)n2->proto;
	if (n1->nsrc[0] != n2->nsrc[0])
		return (int)n1->nsrc[0] - (int)n2->nsrc[0];
	if (n1->nsrc[1] != n2->nsrc[1])
		return (int)n1->nsrc[1] - (int)n2->nsrc[1];
	if (n1->nsrc[2] != n2->nsrc[2])
		return (int)n1->nsrc[2] - (int)n2->nsrc[2];
	if (n1->nsrc[3] != n2->nsrc[3])
		return (int)n1->nsrc[3] - (int)n2->nsrc[3];
	if (n1->nport[0] != n2->nport[0])
		return (int)n1->nport[0] - (int)n2->nport[0];
	if (n1->nport[1] != n2->nport[1])
		return (int)n1->nport[1] - (int)n2->nport[1];
	if (n1->flags & ALL_DST) {
		if (n2->flags & ALL_DST) {
			if (n1->flags & PRR_NULL) {
				if (n2->flags & PRR_NULL)
					return 0;
				else
					return -1;
			} else if (n2->flags & PRR_NULL)
				return 1;
			else
				return 0;
		} else
			return -1;
	}
	if (n1->dst[0] != n2->dst[0])
		return (int)n1->dst[0] - (int)n2->dst[0];
	if (n1->dst[1] != n2->dst[1])
		return (int)n1->dst[1] - (int)n2->dst[1];
	if (n1->dst[2] != n2->dst[2])
		return (int)n1->dst[2] - (int)n2->dst[2];
	if (n1->dst[3] != n2->dst[3])
		return (int)n1->dst[3] - (int)n2->dst[3];
	if ((n1->flags & MATCH_ANY) == 0)
		return 0;
	if (n1->dport[0] != n2->dport[0])
		return (int)n1->dport[0] - (int)n2->dport[0];
	if (n1->dport[1] != n2->dport[1])
		return (int)n1->dport[1] - (int)n2->dport[1];
	return 0;
}

int
nat_tree_compare_wild(struct nat *n1, struct nat *n2)
{
	if (n1->proto != n2->proto)
		return (int)n1->proto - (int)n2->proto;
	if (n1->nsrc[0] != n2->nsrc[0])
		return (int)n1->nsrc[0] - (int)n2->nsrc[0];
	if (n1->nsrc[1] != n2->nsrc[1])
		return (int)n1->nsrc[1] - (int)n2->nsrc[1];
	if (n1->nsrc[2] != n2->nsrc[2])
		return (int)n1->nsrc[2] - (int)n2->nsrc[2];
	if (n1->nsrc[3] != n2->nsrc[3])
		return (int)n1->nsrc[3] - (int)n2->nsrc[3];
	if (n1->nport[0] != n2->nport[0])
		return (int)n1->nport[0] - (int)n2->nport[0];
	if (n1->nport[1] != n2->nport[1])
		return (int)n1->nport[1] - (int)n2->nport[1];
	if ((n1->flags | n2->flags) & ALL_DST)
		return 0;
	if (n1->dst[0] != n2->dst[0])
		return (int)n1->dst[0] - (int)n2->dst[0];
	if (n1->dst[1] != n2->dst[1])
		return (int)n1->dst[1] - (int)n2->dst[1];
	if (n1->dst[2] != n2->dst[2])
		return (int)n1->dst[2] - (int)n2->dst[2];
	if (n1->dst[3] != n2->dst[3])
		return (int)n1->dst[3] - (int)n2->dst[3];
	if ((n1->flags & MATCH_ANY) == 0)
		return 0;
	if (n1->dport[0] != n2->dport[0])
		return (int)n1->dport[0] - (int)n2->dport[0];
	if (n1->dport[1] != n2->dport[1])
		return (int)n1->dport[1] - (int)n2->dport[1];
	return 0;
}

int
nat_splay_compare_abs(struct nat *n1, struct nat *n2)
{
	if (n1->tunnel != n2->tunnel)
		return (int)(n1->tunnel - n2->tunnel);
	if (n1->proto != n2->proto)
		return (int)n1->proto - (int)n2->proto;
	if (n1->src[0] != n2->src[0])
		return (int)n1->src[0] - (int)n2->src[0];
	if (n1->src[1] != n2->src[1])
		return (int)n1->src[1] - (int)n2->src[1];
	if (n1->src[2] != n2->src[2])
		return (int)n1->src[2] - (int)n2->src[2];
	if (n1->src[3] != n2->src[3])
		return (int)n1->src[3] - (int)n2->src[3];
	if (n1->sport[0] != n2->sport[0])
		return (int)n1->sport[0] - (int)n2->sport[0];
	if (n1->sport[1] != n2->sport[1])
		return (int)n1->sport[1] - (int)n2->sport[1];
	if (n1->flags & ALL_DST) {
		if (n2->flags & ALL_DST) {
			if (n1->flags & PRR_NULL) {
				if (n2->flags & PRR_NULL)
					return 0;
				else
					return -1;
			} else if (n2->flags & PRR_NULL)
				return 1;
			else
				return 0;
		} else
			return -1;
	}
	if (n1->dst[0] != n2->dst[0])
		return (int)n1->dst[0] - (int)n2->dst[0];
	if (n1->dst[1] != n2->dst[1])
		return (int)n1->dst[1] - (int)n2->dst[1];
	if (n1->dst[2] != n2->dst[2])
		return (int)n1->dst[2] - (int)n2->dst[2];
	if (n1->dst[3] != n2->dst[3])
		return (int)n1->dst[3] - (int)n2->dst[3];
	if ((n1->flags & MATCH_ANY) == 0)
		return 0;
	if (n1->dport[0] != n2->dport[0])
		return (int)n1->dport[0] - (int)n2->dport[0];
	if (n1->dport[1] != n2->dport[1])
		return (int)n1->dport[1] - (int)n2->dport[1];
	return 0;
}

int
nat_splay_compare_wild(struct nat *n1, struct nat *n2)
{
	if (n1->tunnel != n2->tunnel)
		return (int)(n1->tunnel - n2->tunnel);
	if (n1->proto != n2->proto)
		return (int)n1->proto - (int)n2->proto;
	if (n1->src[0] != n2->src[0])
		return (int)n1->src[0] - (int)n2->src[0];
	if (n1->src[1] != n2->src[1])
		return (int)n1->src[1] - (int)n2->src[1];
	if (n1->src[2] != n2->src[2])
		return (int)n1->src[2] - (int)n2->src[2];
	if (n1->src[3] != n2->src[3])
		return (int)n1->src[3] - (int)n2->src[3];
	if (n1->sport[0] != n2->sport[0])
		return (int)n1->sport[0] - (int)n2->sport[0];
	if (n1->sport[1] != n2->sport[1])
		return (int)n1->sport[1] - (int)n2->sport[1];
	if ((n1->flags | n2->flags) & ALL_DST)
		return 0;
	if (n1->dst[0] != n2->dst[0])
		return (int)n1->dst[0] - (int)n2->dst[0];
	if (n1->dst[1] != n2->dst[1])
		return (int)n1->dst[1] - (int)n2->dst[1];
	if (n1->dst[2] != n2->dst[2])
		return (int)n1->dst[2] - (int)n2->dst[2];
	if (n1->dst[3] != n2->dst[3])
		return (int)n1->dst[3] - (int)n2->dst[3];
	if ((n1->flags & MATCH_ANY) == 0)
		return 0;
	if (n1->dport[0] != n2->dport[0])
		return (int)n1->dport[0] - (int)n2->dport[0];
	if (n1->dport[1] != n2->dport[1])
		return (int)n1->dport[1] - (int)n2->dport[1];
	return 0;
}

/* Red-Black NAT tree routines */

void
nat_tree_rotate_left(u_char pr, struct nat *n, struct nat *tmp)
{
	tmp = n->right;
	if ((n->right = tmp->left) != NULL)
		tmp->left->parent = n;
	if ((tmp->parent = n->parent) != NULL) {
		if (n == n->parent->left)
			n->parent->left = tmp;
		else
			n->parent->right = tmp;
	} else
		nat_tree[pr] = tmp;
	tmp->left = n;
	n->parent = tmp;
}

void
nat_tree_rotate_right(u_char pr, struct nat *n, struct nat *tmp)
{
	tmp = n->left;
	if ((n->left = tmp->right) != NULL)
		tmp->right->parent = n;
	if ((tmp->parent = n->parent) != NULL) {
		if (n == n->parent->left)
			n->parent->left = tmp;
		else
			n->parent->right = tmp;
	} else
		nat_tree[pr] = tmp;
	tmp->right = n;
	n->parent = tmp;
}

void
nat_tree_insert_color(u_char pr, struct nat *n)
{
	struct nat *parent, *gparent, *tmp;

	while (((parent = n->parent) != NULL) &&
	       (parent->color == RB_RED)) {
		gparent = parent->parent;
		if (parent == gparent->left) {
			tmp = gparent->right;
			if ((tmp != NULL) && (tmp->color == RB_RED)) {
				tmp->color = RB_BLACK;
				parent->color = RB_BLACK;
				gparent->color = RB_RED;
				n = gparent;
				continue;
			}
			if (parent->right == n) {
				nat_tree_rotate_left(pr, parent, tmp);
				tmp = parent;
				parent = n;
				n = tmp;
			}
			parent->color = RB_BLACK;
			gparent->color = RB_RED;
			nat_tree_rotate_right(pr, gparent, tmp);
		} else {
			tmp = gparent->left;
			if ((tmp != NULL) && (tmp->color == RB_RED)) {
				tmp->color = RB_BLACK;
				parent->color = RB_BLACK;
				gparent->color = RB_RED;
				n = gparent;
				continue;
			}
			if (parent->left == n) {
				nat_tree_rotate_right(pr, parent, tmp);
				tmp = parent;
				parent= n;
				n = tmp;
			}
			parent->color = RB_BLACK;
			gparent->color = RB_RED;
			nat_tree_rotate_left(pr, gparent, tmp);
		}
	}
	nat_tree[pr]->color = RB_BLACK;
}

void
nat_tree_remove_color(u_char pr, struct nat *parent, struct nat *n)
{
	struct nat *tmp;

	while (((n == NULL) || (n->color == RB_BLACK)) &&
	       (n != nat_tree[pr])) {
		if (parent->left == n) {
			tmp = parent->right;
			if (tmp->color == RB_RED) {
				tmp->color = RB_BLACK;
				parent->color = RB_RED;
				nat_tree_rotate_left(pr, parent, tmp);
				tmp = parent->right;
			}
			if (((tmp->left == NULL) ||
			     (tmp->left->color == RB_BLACK)) &&
			    ((tmp->right == NULL) ||
			     (tmp->right->color == RB_BLACK))) {
				tmp->color = RB_RED;
				n = parent;
				parent = n->parent;
			} else {
				if ((tmp->right == NULL) ||
				    (tmp->right->color == RB_BLACK)) {
					struct nat *oleft = tmp->left;

					if (oleft != NULL)
						oleft->color = RB_BLACK;
					tmp->color = RB_RED;
					nat_tree_rotate_right(pr, tmp, oleft);
					tmp = parent->right;
				}
				tmp->color = parent->color;
				parent->color = RB_BLACK;
				if (tmp->right != NULL)
					tmp->right->color = RB_BLACK;
				nat_tree_rotate_left(pr, parent, tmp);
				n = nat_tree[pr];
				break;
			}
		} else {
			tmp = parent->left;
			if (tmp->color == RB_RED) {
				tmp->color = RB_BLACK;
				parent->color = RB_RED;
				nat_tree_rotate_right(pr, parent, tmp);
				tmp = parent->left;
			}
			if (((tmp->left == NULL) ||
			     (tmp->left->color == RB_BLACK)) &&
			    ((tmp->right == NULL) ||
			     (tmp->right->color== RB_BLACK))) {
				tmp->color = RB_RED;
				n = parent;
				parent = n->parent;
			} else {
				if ((tmp->left == NULL) ||
				    (tmp->left->color == RB_BLACK)) {
					struct nat *oright = tmp->right;

					if (oright != NULL)
						oright->color = RB_BLACK;
					tmp->color = RB_RED;
					nat_tree_rotate_left(pr, tmp, oright);
					tmp = parent->left;
				}
				tmp->color = parent->color;
				parent->color = RB_BLACK;
				if (tmp->left != NULL)
					tmp->left->color = RB_BLACK;
				nat_tree_rotate_right(pr, parent, tmp);
				n = nat_tree[pr];
				break;
			}
		}
	}
	if (n != NULL)
		n->color = RB_BLACK;
}

struct nat *
nat_tree_remove(u_char pr, struct nat *n)
{
	struct nat *child, *parent, *old = n;
	u_char color;

	if (n->left == NULL)
		child = n->right;
	else if (n->right == NULL)
		child = n->left;
	else {
		struct nat *left;

		n = n->right;
		while ((left = n->left) != NULL)
			n = left;
		child = n->right;
		parent = n->parent;
		color = n->color;
		if (child != NULL)
			child->parent = parent;
		if (parent != NULL) {
			if (parent->left == n)
				parent->left = child;
			else
				parent->right = child;
		} else
			nat_tree[pr] = child;
		if (n->parent == old)
			parent = n;
		n->left = old->left;
		n->right = old->right;
		n->parent = old->parent;
		n->color = old->color;
		if (old->parent != NULL) {
			if (old->parent->left == old)
				old->parent->left = n;
			else
				old->parent->right = n;
		} else
			nat_tree[pr] = n;
		old->left->parent = n;
		if (old->right != NULL)
			old->right->parent = n;
		if (parent != NULL) {
			left = parent;
			do { /* void */
			} while ((left = left->parent) != NULL);
		}
		goto color;
	}
	parent = n->parent;
	color = n->color;
	if (child != NULL)
		child->parent = parent;
	if (parent != NULL) {
		if (parent->left == n)
			parent->left = child;
		else
			parent->right = child;
	} else
		nat_tree[pr] = child;
    color:
	if (color == RB_BLACK)
		nat_tree_remove_color(pr, parent, child);
	return old;
}

struct nat *
nat_tree_insert(u_char pr, struct nat *n)
{
	struct nat *tmp = nat_tree[pr], *parent = NULL;
	int comp = 0;

	while (tmp != NULL) {
		parent = tmp;
		comp = nat_tree_compare_abs(n, parent);
		if (comp < 0)
			tmp = tmp->left;
		else if (comp > 0)
			tmp = tmp->right;
		else
			return tmp;
	}
	n->parent = parent;
	n->left = n->right = NULL;
	n->color = RB_RED;
	if (parent != NULL) {
		if (comp < 0)
			parent->left = n;
		else
			parent->right = n;
	} else
		nat_tree[pr] = n;
	nat_tree_insert_color(pr, n);
	return NULL;
}

struct nat *
nat_tree_find_wild(u_char pr, struct nat *n)
{
	struct nat *tmp = nat_tree[pr];
	int comp;

	while (tmp != NULL) {
		comp = nat_tree_compare_wild(n, tmp);
		if (comp < 0)
			tmp = tmp->left;
		else if (comp > 0)
			tmp = tmp->right;
		else
			return tmp;
	}
	return NULL;
}

struct nat *
nat_tree_min(u_char pr)
{
	struct nat *tmp = nat_tree[pr];
	struct nat *parent = NULL;

	while (tmp != NULL) {
		parent = tmp;
		tmp = tmp->left;
	}
	return parent;
}

struct nat *
nat_tree_next(struct nat *n)
{
	if (n->right != NULL) {
		n = n->right;
		while (n->left != NULL)
			n = n->left;
	} else {
		if ((n->parent != NULL) && (n == n->parent->left))
			n = n->parent;
		else {
			while ((n->parent != NULL) && (n == n->parent->right))
				n = n->parent;
			n = n->parent;
		}
	}
	return n;
}

/* Per tunnel splay tree */

inline void
nat_splay_rotate_right(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;

	t->tnat_root[pr]->tleft = n->tright;
	n->tright = t->tnat_root[pr];
	t->tnat_root[pr] = n;
}

inline void
nat_splay_rotate_left(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;

	t->tnat_root[pr]->tright = n->tleft;
	n->tleft = t->tnat_root[pr];
	t->tnat_root[pr] = n;
}

inline struct nat *
nat_splay_link_right(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;

	n->tright = t->tnat_root[pr];
	n = t->tnat_root[pr];
	t->tnat_root[pr] = t->tnat_root[pr]->tright;
	return n;
}

inline struct nat *
nat_splay_link_left(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;

	n->tleft = t->tnat_root[pr];
	n = t->tnat_root[pr];
	t->tnat_root[pr] = t->tnat_root[pr]->tleft;
	return n;
}

inline void
nat_splay_assemble(u_char pr, struct nat *n,
		   struct nat *left, struct nat *right)
{
	struct tunnel *t = n->tunnel;

	left->tright = t->tnat_root[pr]->tleft;
	right->tleft = t->tnat_root[pr]->tright;
	t->tnat_root[pr]->tleft = n->tright;
	t->tnat_root[pr]->tright = n->tleft;
}

void
nat_splay_splay(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;
	struct nat node, *left, *right, *tmp;
	int comp;

	if (t->tnat_root[pr] == NULL)
		return;
	node.tunnel = n->tunnel;
	node.tleft = node.tright = NULL;
	left = right = &node;
	while ((comp = nat_splay_compare_abs(n, t->tnat_root[pr])) != 0) {
		if (comp < 0) {
			tmp = t->tnat_root[pr]->tleft;
			if (tmp == NULL)
				break;
			if (nat_splay_compare_abs(n, tmp) < 0) {
				nat_splay_rotate_right(pr, tmp);
				if (t->tnat_root[pr]->tleft == NULL)
					break;
			}
			right = nat_splay_link_left(pr, right);
		} else if (comp > 0) {
			tmp = t->tnat_root[pr]->tright;
			if (tmp == NULL)
				break;
			if (nat_splay_compare_abs(n, tmp) > 0) {
				nat_splay_rotate_left(pr, tmp);
				if (t->tnat_root[pr]->tright == NULL)
					break;
			}
			left = nat_splay_link_right(pr, left);
		}
	}
	nat_splay_assemble(pr, &node, left, right);
}

void
nat_splay_splay_wild(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;
	struct nat node, *left, *right, *tmp;
	int comp;

	if (t->tnat_root[pr] == NULL)
		return;
	node.tunnel = n->tunnel;
	node.tleft = node.tright = NULL;
	left = right = &node;
	while ((comp = nat_splay_compare_wild(n, t->tnat_root[pr])) != 0) {
		if (comp < 0) {
			tmp = t->tnat_root[pr]->tleft;
			if (tmp == NULL)
				break;
			if (nat_splay_compare_wild(n, tmp) < 0) {
				nat_splay_rotate_right(pr, tmp);
				if (t->tnat_root[pr]->tleft == NULL)
					break;
			}
			right = nat_splay_link_left(pr, right);
		} else if (comp > 0) {
			tmp = t->tnat_root[pr]->tright;
			if (tmp == NULL)
				break;
			if (nat_splay_compare_wild(n, tmp) > 0) {
				nat_splay_rotate_left(pr, tmp);
				if (t->tnat_root[pr]->tright == NULL)
					break;
			}
			left = nat_splay_link_right(pr, left);
		}
	}
	nat_splay_assemble(pr, &node, left, right);
}

struct nat *
nat_splay_insert(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;

	if (t->tnat_root[pr] == NULL)
		n->tleft = n->tright = NULL;
	else {
		int comp;

		nat_splay_splay(pr, n);
		comp = nat_splay_compare_abs(n, t->tnat_root[pr]);
		if (comp < 0) {
			n->tleft = t->tnat_root[pr]->tleft;
			n->tright = t->tnat_root[pr];
			t->tnat_root[pr]->tleft = NULL;
		} else if (comp > 0) {
			n->tright = t->tnat_root[pr]->tright;
			n->tleft = t->tnat_root[pr];
			t->tnat_root[pr]->tright = NULL;
		} else
			return t->tnat_root[pr];
	}
	t->tnat_root[pr] = n;
	return NULL;
}

struct nat *
nat_splay_remove(u_char pr, struct nat *n)
{
	struct tunnel *t = n->tunnel;
	
	if (t->tnat_root[pr] == NULL)
		return NULL;
	nat_splay_splay(pr, n);
	if (nat_splay_compare_abs(n, t->tnat_root[pr]) == 0) {
		if (t->tnat_root[pr]->tleft == NULL)
			t->tnat_root[pr] = t->tnat_root[pr]->tright;
		else {
			struct nat *tmp;

			tmp = t->tnat_root[pr]->tright;
			t->tnat_root[pr] = t->tnat_root[pr]->tleft;
			nat_splay_splay(pr, n);
			t->tnat_root[pr]->tright = tmp;
		}
		return n;
	}
	return NULL;
}

struct nat *
nat_splay_find(u_char pr, struct nat *n, int exact, int stale)
{
	struct tunnel *t = n->tunnel;

	if (t->tnat_root[pr] == NULL)
		return NULL;
	if (exact) {
		nat_splay_splay(pr, n);
		if (nat_splay_compare_abs(n, t->tnat_root[pr]) == 0) {
			if (!stale &&
			    (n->generation >= FIRSTGEN) &&
			    (n->generation < lastgen)) {
				logdebug(10, "in: stale NAT entry %lx",
					 (u_long) t->tnat_root[pr]);
				return NULL;
			}
			return t->tnat_root[pr];
		}
	} else {
		nat_splay_splay_wild(pr, n);
		if (nat_splay_compare_wild(n, t->tnat_root[pr]) == 0) {
			if (!stale &&
			    (n->generation >= FIRSTGEN) &&
			    (n->generation < lastgen)) {
				logdebug(10, "in: stale NAT entry %lx",
					 (u_long) t->tnat_root[pr]);
				return NULL;
			}
			return t->tnat_root[pr];
		}
	}
	return NULL;
}

/* read-only find */

struct nat *
nat_splay_ro_find(u_char pr, struct nat *n, int exact)
{
	struct tunnel *t = n->tunnel;
	struct nat *tmp;
	int comp;

	tmp = t->tnat_root[pr];
	while (tmp != NULL) {
		if (exact)
			comp = nat_splay_compare_abs(n, tmp);
		else
			comp = nat_splay_compare_wild(n, tmp);
		if (comp < 0)
			tmp = tmp->tleft;
		else if (comp > 0)
			tmp = tmp->tright;
		else
			return tmp;
	}
	return NULL;
}

/* min/max/next... */

/* NAT heap */

/* resize */

int
nat_heap_resize(void)
{
	struct nat **nh;
	u_int ns = nat_heap_size + 1024;

	nh = (struct nat **) malloc(ns * sizeof(*nh));
	if (nh == NULL) {
		logerr("malloc(heap): %s\n", strerror(errno));
		return 0;
	}
	if (nat_heap != NULL) {
		memcpy(nh, nat_heap, nat_heap_size * sizeof(*nh));
		free(nat_heap);
	}
	nat_heap = nh;
	nat_heap_size = ns;
	return 1;
}

/* parent is i/2, left child is i*2 and right child is i*2+1 */

void
nat_heap_float_up(u_int i, struct nat *n)
{
	u_int p;

	for (p = i >> 1;
	     (i > 1) && (n->timeout < nat_heap[p]->timeout);
	     i = p, p = i >> 1) {
		nat_heap[i] = nat_heap[p];
		nat_heap[i]->heap_index = i;
	}
	nat_heap[i] = n;
	nat_heap[i]->heap_index = i;

	if ((i > 1) && (nat_heap[i]->timeout < nat_heap[i >> 1]->timeout))
		logcrit("nat_heap_float_up[%u]\n", i);
}

void
nat_heap_sink_down(u_int i, struct nat *n)
{
	u_int j, size, half;

	size = nat_heap_last;
	half = size / 2;
	while (i <= half) {
		/* Find the smallest of the (at most) two children */
		j = i << 1;
		if ((j < size) &&
		    (nat_heap[j + 1]->timeout < nat_heap[j]->timeout))
			j++;
		if (n->timeout < nat_heap[j]->timeout)
			break;
		nat_heap[i] = nat_heap[j];
		nat_heap[i]->heap_index = i;
		i = j;
	}
	nat_heap[i] = n;
	nat_heap[i]->heap_index = i;

	if ((i > 1) && (nat_heap[i]->timeout < nat_heap[i >> 1]->timeout))
		logcrit("nat_heap_sink_down[%u]\n", i);
}

int
nat_heap_insert(struct nat *n)
{
	u_int new_last;

	new_last = nat_heap_last + 1;
	if ((new_last >= nat_heap_size) && !nat_heap_resize())
		return 0;
	nat_heap_last = new_last;
	nat_heap_float_up(new_last, n);
	return 1;
}

void
nat_heap_delete(u_int i)
{
	struct nat *n;
	int less;

	if ((i < 1) || (i > nat_heap_last)) {
		logcrit("nat_heap_delete[%u]\n", i);
		return;
	}

	if (i == nat_heap_last) {
		nat_heap[nat_heap_last] = NULL;
		ISC_DECR(nat_heap_last, "nat_heap_last");
		return;
	}
	n = nat_heap[nat_heap_last];
	nat_heap[nat_heap_last] = NULL;
	ISC_DECR(nat_heap_last, "nat_heap_last");

	less = (n->timeout < nat_heap[i]->timeout);
	nat_heap[i] = n;
	if (less)
		nat_heap_float_up(i, nat_heap[i]);
	else
		nat_heap_sink_down(i, nat_heap[i]);
}

void
nat_heap_increased(u_int i)
{
	if ((i < 1) || (i > nat_heap_last)) {
		logcrit("nat_heap_increased[%u]\n", i);
		return;
	}

	nat_heap_float_up(i, nat_heap[i]);
}

void
nat_heap_decreased(u_int i)
{
	if ((i < 1) || (i > nat_heap_last)) {
		logcrit("nat_heap_decreased[%u]\n", i);
		return;
	}

	nat_heap_sink_down(i, nat_heap[i]);
}

struct nat *
nat_heap_element(u_int i)
{
	if (i < 1) {
		logcrit("nat_heap_element[%u]\n", i);
		return NULL;
	}

	if (i <= nat_heap_last)
		return nat_heap[i];
	return NULL;
}

/* Tunnel radix (patricia) tree routines */

struct tunnel *
tunnel_tree_find(struct tunnel *t)
{
	struct tunnel *node = tunnel_tree;

	if (tunnel_tree == NULL)
		return NULL;
	while (node->bit < MAXTUNBIT) {
		if (t->key[node->bit >> 3] & (0x80 >> (node->bit & 7)))
			node = node->right;
		else
			node = node->left;
		if (node == NULL)
			return NULL;
	}
	if ((node->bit > MAXTUNBIT) || ((node->flags & TUNGLUE) != 0))
		return NULL;
	if (node->bit != MAXTUNBIT)
		logcrit("PATRICIA0\n");
	if (memcmp(node->key, t->key, sizeof(t->key)) == 0)
		return node;
	return NULL;
}

struct tunnel *
tunnel_tree_insert(struct tunnel *t, u_int *exposing)
{
	struct tunnel *node, *parent, *glue;
	u_int i, j, r, check, differ;

	*exposing = 0;
	if (tunnel_tree == NULL) {
		t->parent = NULL;
		t->left = t->right = NULL;
		t->bit = MAXTUNBIT;
		tunnel_tree = t;
		return NULL;
	}
	node = tunnel_tree;
	while ((node->bit < MAXTUNBIT) || ((node->flags & TUNGLUE) != 0)) {
		if (t->key[node->bit >> 3] & (0x80 >> (node->bit & 7))) {
			if (node->right == NULL)
				break;
			node = node->right;
		} else {
			if (node->left == NULL)
				break;
			node = node->left;
		}
		if (node == NULL) {
			logcrit("PATRICIA1\n");
			return NULL;
		}
	}
	if ((node->flags & TUNGLUE) != 0)
		logcrit("PATRICIA2\n");
	if (node->bit < MAXTUNBIT)
		check = node->bit;
	else
		check = MAXTUNBIT;
	differ = 0;
	for (i = 0; (i << 3) < check; i++) {
		if ((r = (t->key[i] ^ node->key[i])) == 0) {
			differ = (i + 1) << 3;
			continue;
		}
		for (j = 0; j < 8; j++)
			if (r & (0x80 >> j))
				break;
		if (j >= 8)
			logcrit("PATRICIA3\n");
		differ = (i << 3) + j;
		break;
	}
	if (differ > check)
		differ = check;
	parent = node->parent;
	while ((parent != NULL) && (parent->bit >= differ)) {
		node = parent;
		parent = node->parent;
	}
	if ((differ == MAXTUNBIT) && (node->bit == MAXTUNBIT)) {
		if ((node->flags & TUNGLUE) == 0)
			return node;
		memcpy(node->key, t->key, sizeof(t->key));
		node->flags = 0;
		*exposing = 1;
		return node;
	}
	t->bit = MAXTUNBIT;
	if (node->bit == differ) {
		t->parent = node;
		if ((node->bit < MAXTUNBIT) &&
		    (t->key[node->bit >> 3] & (0x80 >> (node->bit & 7)))) {
			if (node->right != NULL)
				logcrit("PATRICIA4\n");
			node->right = t;
		} else {
			if (node->left != NULL)
				logcrit("PATRICIA5\n");
			node->left = t;
		}
		return NULL;
	}
	if (differ == MAXTUNBIT) {
		t->left = node;
		t->parent = node->parent;
		if (node->parent == NULL) {
			if (tunnel_tree != node)
				logcrit("PATRICIA6\n");
			tunnel_tree = t;
		} else if (node->parent->right == node)
			node->parent->right = t;
		else
			node->parent->left = t;
		node->parent = t;
		return NULL;
	}
	glue = (struct tunnel *) malloc(sizeof(*t));
	if (glue == NULL) {
		logerr("malloc(tunnel_tree_insert): %s\n", strerror(errno));
		return t;
	}
	memset(glue, 0, sizeof(*t));
	ISC_MAGIC_SET(glue, ISC_TUNNEL_MAGIC);
	glue->flags |= TUNGLUE;
	glue->parent = node->parent;
	glue->bit = differ;
	if ((differ < MAXTUNBIT) &&
	    (t->key[differ >> 3] & (0x80 >> (differ & 7)))) {
		glue->right = t;
		glue->left = node;
	} else {
		glue->right = node;
		glue->left = t;
	}
	t->parent = glue;
	if (node->parent == NULL) {
		if (tunnel_tree != node)
			logcrit("PATRICIA7\n");
		tunnel_tree = glue;
	} else if (node->parent->right == node)
		node->parent->right = glue;
	else
		node->parent->left = glue;
	node->parent = glue;
	return NULL;
}

void
tunnel_tree_remove(struct tunnel *t)
{
	struct tunnel *parent, *child;

	if ((t->right != NULL) && (t->left != NULL)) {
		t->flags |= TUNGLUE;
		return;
	}
	if ((t->right == NULL) && (t->left == NULL)) {
		parent = t->parent;
		t->flags |= TUNGLUE;
		ISC_MAGIC_FREE(t, ISC_TUNNEL_MAGIC);
		free(t);
		if (parent == NULL) {
			if (tunnel_tree != t)
				logcrit("PATRICIA8\n");
			tunnel_tree = NULL;
			return;
		}
		if (parent->right == t) {
			parent->right = NULL;
			child = parent->left;
		} else {
			parent->left = NULL;
			child = parent->right;
		}
		if ((parent->flags & TUNGLUE) == 0)
			return;
		if (parent->parent == NULL) {
			if (tunnel_tree != parent)
				logcrit("PATRICIA9\n");
			tunnel_tree = child;
		} else if (parent->parent->right == parent)
			parent->parent->right = child;
		else {
			if (parent->parent->left != parent)
				logcrit("PATRICIAa\n");
			parent->parent->left = child;
		}
		child->parent = parent->parent;
		ISC_MAGIC_FREE(parent, ISC_TUNNEL_MAGIC);
		free(parent);
		return;
	}
	if (t->right != NULL)
		child = t->right;
	else {
		if (t->left == NULL)
			logcrit("PATRICIAb\n");
		child = t->left;
	}
	parent = t->parent;
	child->parent = parent;
	t->flags |= TUNGLUE;
	ISC_MAGIC_FREE(t, ISC_TUNNEL_MAGIC);
	free(t);
	if (parent == NULL) {
		if (tunnel_tree != t)
			logcrit("PATRICIAc\n");
		tunnel_tree = child;
		return;
	}
	if (parent->right == t)
		parent->right = child;
	else {
		if (parent->left != t)
			logcrit("PATRICIAd\n");
		parent->left = child;
	}
}

/*
 * Data structures
 *	lookup/del/add/set...
 */

/* Lookup matching NAT */

struct nat *
nat_lookup(u_char pr, struct nat *nat0)
{
	struct nat *n;
	u_short hash;

	tnhlookups++, pnhlookups++;
	hash = jhash_nat(nat0);
	hash &= nathashsz - 1;
	n = nathash[hash];
	if ((n != NULL) && (nat_tree_compare_wild(nat0, n) == 0)) {
		tnhhits++, pnhhits++;
		return n;
	}
	n = nat_tree_find_wild(pr, nat0);
	if (n == NULL)
		return NULL;
	if ((n->generation >= FIRSTGEN) && (n->generation < lastgen)) {
		logdebug(10, "out: stale NAT entry %lx", (u_long) n);
		return NULL;
	}
	n->hash = hash;
	nathash[hash] = n;
	return n;
}

/* lookup a matching tunnel */

struct tunnel *
tunnel_lookup(u_char *peer)
{
	struct tunnel *t, tunnel0;
	u_short hash;

	tthlookups++, pthlookups++;
	hash = jhash_tunnel(peer);
	hash &= tunhashsz - 1;
	t = tunhash[hash];
	if ((t != NULL) && (memcmp(peer, t->remote, 16) == 0)) {
		tthhits++, pthhits++;
		return t;
	}
	memcpy(tunnel0.remote, peer, 16);
	t = tunnel_tree_find(&tunnel0);
	if (t == NULL)
		return NULL;
	t->hash = hash;
	tunhash[hash] = t;
	return t;
}

/* Delete a fragment chain */

void
del_frag4(struct frag *f)
{
	struct frag *p, *q;

	for (p = ISC_SLIST_FIRST(&f->fraglist); p != NULL; p = q) {
		q = ISC_SLIST_NEXT(p, fragchain);
		free(p->buf);
		ISC_MAGIC_FREE(p, ISC_FRAGMENT_MAGIC);
		free(p);
	}
	free(f->buf);
	if (f->tunnel == NULL)
		ISC_TAILQ_REMOVE(&fragsout, f, ffragchain);
	else
		ISC_TAILQ_REMOVE(&fragsin, f, ffragchain);
	if ((f->hash < fraghashsz) && (fraghash[f->hash] == f))
		fraghash[f->hash] = NULL;
	if (f->tunnel != NULL) {
		ISC_DECR(fragsincnt, "fragsincnt");
		ISC_DECR(f->tunnel->frg4cnt, "frg4cnt");
	} else
		ISC_DECR(fragsoutcnt, "fragsoutcnt");
	ISC_MAGIC_FREE(f, ISC_FRAGMENT_MAGIC);
	free(f);
}

void
del_frag6(struct frag *f)
{
	struct frag *p, *q;

	for (p = ISC_SLIST_FIRST(&f->fraglist); p != NULL; p = q) {
		q = ISC_SLIST_NEXT(p, fragchain);
		free(p->buf);
		ISC_MAGIC_FREE(p, ISC_FRAGMENT_MAGIC);
		free(p);
	}
	free(f->buf);
	ISC_TAILQ_REMOVE(&frags6, f, ffragchain);
	ISC_DECR(frags6cnt, "frags6cnt");
	ISC_DECR(f->tunnel->frg6cnt, "frg6cnt");
	ISC_MAGIC_FREE(f, ISC_FRAGMENT_MAGIC);
	free(f);
}

/* Delete a NAT entry */

void
del_nat(struct nat *n)
{
	struct tunnel *t = n->tunnel;
	struct pool *ns;
	struct nat *f;
	struct held *h;
	struct ftpseq *fs;
	u_int i;
	u_char pr;

	if (n->flags & ALL_DST) {
		if (n->flags & PRR_NULL)
			ISC_DECR(prrcnt, "prrcnt");
		else
			ISC_DECR(snatcnt, "snatcnt");
		switch (n->proto) {
		case IPTCP:
			pr = TCPPR;
			break;
		case IPUDP:
			pr = UDPPR;
			break;
		default:
			pr = ICMPPR;
			break;
		}
	} else switch (n->proto) {
		case IPTCP:
			ISC_DECR(natcntt, "natcntt");
			pr = TCPPR;
			break;
		case IPUDP:
			ISC_DECR(natcntu, "natcntu");
			pr = UDPPR;
			break;
		default:
			ISC_DECR(natcnto, "natcnto");
			pr = ICMPPR;
			break;
		}
	statsdnat++;
	if (t->flags & TUNDEBUG)
		debugdnat++;
#ifdef TRACE_NAT
	if (n->proto != IPICMP)
		trace_nat(n, "del");
#endif
	logdebug(10, "del_nat");
	if (n->heap_index)
		nat_heap_delete(n->heap_index);
	n->heap_index = 0;

	while ((f = ISC_LIST_FIRST(&n->xlist)) != NULL)
		ISC_LIST_REMOVE(f, xchain);
	if (ISC_LIST_PREV(n, xchain) != NULL)
		ISC_LIST_REMOVE(n, xchain);
	while ((fs = ISC_SLIST_FIRST(&n->ftpseq)) != NULL) {
		ISC_SLIST_REMOVE_HEAD(&n->ftpseq, chain);
		ISC_MAGIC_FREE(fs, ISC_FTPSEQ_MAGIC);
		free(fs);
	}
	if (ISC_LIST_PREV(n, gchain) != NULL) {
		/* should not happen but in case... */
		if (n == gc_ptr)
			gc_ptr = ISC_LIST_NEXT(n, gchain);
		if (n == bt_ptr)
			bt_ptr = ISC_LIST_NEXT(n, gchain);
		ISC_LIST_REMOVE(n, gchain);
	}

	if (nat_tree_remove(pr, n) == NULL)
		logcrit("rb not found(del_nat)\n");
	if (nat_splay_remove(pr, n) == NULL)
		logcrit("splay not found(del_nat)\n");
	ISC_DECR(t->tnatcnt[pr], "tnatcnt");

	if ((n->hash < nathashsz) && (nathash[n->hash] == n))
		nathash[n->hash] = NULL;

	ns = pools[t->srcidx];
	if (memcmp(ns->addr, n->nsrc, 4) == 0)
		goto found;
	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		if (memcmp(ns->addr, n->nsrc, 4) == 0)
			goto found;
	}
	logcrit("pool not found(del_nat)\n");
	ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
	free(n);
	return;

    found:
	i = (n->nport[0] << 8) | n->nport[1];
	if ((i < ns->minport[pr]) || (i > ns->maxport[pr])) {
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return;
	}

	h = (struct held *) n;
	ISC_MAGIC_SET(h, ISC_HELD_MAGIC);
	h->flags = ON_HOLD;
	h->timeout = seconds + hold_lifetime;
	ISC_TAILQ_INSERT_TAIL(&ns->helds[pr], h, chain);
}

/* Free held NAT entries */

void
free_heldnats(void)
{
	struct pool *ns;
	struct held *h;
	u_int i, pr, port, cnt = 0;
	u_char *bm;

	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		for (pr = 0; pr < PRCNT; pr++) {
			bm = ns->freebm[pr];
			while ((h = ISC_TAILQ_FIRST(&ns->helds[pr])) != NULL) {
				if (h->timeout > seconds)
					break;
				ISC_TAILQ_REMOVE(&ns->helds[pr], h, chain);
				port = h->nport[0] << 8;
				port |= h->nport[1];
				ISC_MAGIC_FREE(h, ISC_HELD_MAGIC);
				free(h);
				cnt++;
				if ((port < ns->minport[pr]) ||
				    (port > ns->maxport[pr]))
					continue;
				port -= ns->minport[pr];
				bm[port / 8] |= 1 << (port % 8);
				ISC_DECR(ns->natcnt[pr], "natcnt");
			}
		}
	}
	if (cnt > 0)
		logdebug(10, "free %u held nats", cnt);
}

/* Delete a tunnel entry */

int
del_tunnel(struct sess *ss, u_char *peer)
{
	struct tunnel *t;
	struct nat *n;
	struct pool *ns;
	u_short *b, port;
	u_char *bm, i;

	logdebug(10, "del_tunnel");

	t = tunnel_lookup(peer);
	if (t == NULL) {
		sslogerr(ss,
			 "already unbound[%s]\n",
			 addr2str(AF_INET6, peer));
		return -1;
	} else if (t->flags & TUNNONAT) {
		sslogerr(ss, "nonat tunnel[%s]\n", addr2str(AF_INET6, peer));
		return -1;
	}
	ns = pools[t->srcidx];
	for (i = 0; i < PRCNT; i++) {
		while ((n = t->tnat_root[i]) != NULL)
			del_nat(n);
		b = t->bucket[i];
		bm = ns->freebm[i];
		while (t->avail[i] > 0) {
			t->avail[i] -= 1;
			port = b[t->avail[i]];
			if ((port < ns->minport[i]) || (port > ns->maxport[i]))
				continue;
			port -= ns->minport[i];
			bm[port / 8] |= 1 << (port % 8);
		}
		t->bucket[i] = NULL;
	}
	if (t == tunnel_debugged)
		tunnel_debugged = NULL;
	t->flags &= ~TUNDEBUG;
	ISC_DECR(tuncnt, "tuncnt");
	trace_tunnel(t, "del");
	notify("tunnel del %s\n", addr2str(AF_INET6, t->remote));
	if ((t->hash < tunhashsz) && (tunhash[t->hash] == t))
		tunhash[t->hash] = NULL;
	tunnel_tree_remove(t);
	/* t freed by tunnel_tree_remove() */
	return 0;
}

/* Fill a bucket */

void
fill_bucket(struct tunnel *t, int proto)
{
	struct pool *ns;
	u_short *b, port, nb;
	u_char sz, pr, i, found, *bm;

	logdebug(10, "fill bucket");

	switch (proto) {
	case IPTCP:
		pr = TCPPR;
		break;
	case IPUDP:
		pr = UDPPR;
		break;
	default:
		pr = ICMPPR;
		break;
	}
	sz = bucksize[pr];
	ns = pools[t->srcidx];
	bm = ns->freebm[pr];
	if (bm == NULL)
		return;
	b = (u_short *) malloc(sz * sizeof(*b));
	if (b == NULL) {
		logerr("malloc(bucket): %s\n", strerror(errno));
		return;
	}
	memset(b, 0, sz * sizeof(*b));
	t->bucket[pr] = b;
	for (t->avail[pr] = 0; t->avail[pr] < sz; t->avail[pr] += 1) {
		found = 0;
		for (i = 0; i < 10; i++) {
			port = arc4_getport(ns->minport[pr], ns->maxport[pr]);
			nb = port - ns->minport[pr];
			if ((bm[nb / 8] & (1 << (nb % 8))) == 0)
				continue;
			bm[nb / 8] &= ~(1 << (nb % 8));
			b[t->avail[pr]] = port;
			found = 1;
			break;
		}
		if (found)
			continue;
		logdebug(1, "can't get free %s port for %s %s",
			 proto2str(proto),
			 addr2str(AF_INET6, t->remote),
			 addr2str(AF_INET, ns->addr));
		if (t->avail[pr] == 0) {
			t->bucket[pr] = NULL;
			free(b);
			return;
		}
		break;
	}
	if (proto != IPICMP)
		trace_bucket(t, proto);
}

/* Create a new NAT entry (returns 1 if successful, 0 otherwise) */

int
new_nat(struct nat *n)
{
	struct tunnel *t = n->tunnel;
	struct pool *ns = pools[t->srcidx];
	struct held *h;
	u_short *b, port;
	u_char pr;

	logdebug(10, "new_nat");

	switch (n->proto) {
	case IPTCP:
		pr = TCPPR;
		break;
	case IPUDP:
		pr = UDPPR;
		break;
	default:
		pr = ICMPPR;
		break;
	}
	if (t->avail[pr] == 0)
		fill_bucket(t, n->proto);
	b = t->bucket[pr];
	if (b == NULL) {
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return 0;
	}
	ISC_DECR(t->avail[pr], "avail");
	port = b[t->avail[pr]];
	if (t->avail == 0) {
		t->bucket[pr] = NULL;
		free(b);
	}
	n->nport[0] = port >> 8;
	n->nport[1] = port & 0xff;
	ns->natcnt[pr] += 1;

	if (!nat_heap_insert(n))
		goto failed;
	if (nat_tree_insert(pr, n) != NULL) {
		logcrit("new_nat rb collision\n");
		nat_heap_delete(n->heap_index);
		goto failed;
	}
	if (nat_splay_insert(pr, n) != NULL) {
		logcrit("new_nat splay collision\n");
		(void) nat_tree_remove(pr, n);
		nat_heap_delete(n->heap_index);
		goto failed;
	}
	if (n->flags & ALL_DST)
		snatcnt++;
	else
		switch (n->proto) {
		case IPTCP:
			natcntt++;
			break;
		case IPUDP:
			natcntu++;
			break;
		default:
			natcnto++;
			break;
		}
	t->tnatcnt[pr]++;
	statscnat++;
	if (t->flags & TUNDEBUG)
		debugcnat++;
	logdebug(10, "create nat entry");
#ifdef TRACE_NAT
	if (n->proto != IPICMP)
		trace_nat(n, "add");
#endif
	return 1;

    failed:
	h = (struct held *) n;
	ISC_MAGIC_SET(h, ISC_HELD_MAGIC);
	h->flags = ON_HOLD;
	h->timeout = seconds + hold_lifetime;
	ISC_TAILQ_INSERT_TAIL(&ns->helds[pr], h, chain);
	return 0;
}

/* Add a tunnel entry (returns a pointer to the new tunnel,
   or NULL on failure */

struct tunnel *
add_tunnel(struct sess *ss, u_char *peer)
{
	struct tunnel *t, *e;
	u_int exposing = 0;

	logdebug(10, "add_tunnel");

	if (tunnel_lookup(peer) != NULL) {
		sslogerr(ss, "already bound[%s]\n", addr2str(AF_INET6, peer));
		return NULL;
	}

	t = (struct tunnel *) malloc(sizeof(*t));
	if (t == NULL) {
		sslogerr(ss, "malloc(tunnel): %s\n", strerror(errno));
		return NULL;
	}
	memset(t, 0, sizeof(*t));
	ISC_MAGIC_SET(t, ISC_TUNNEL_MAGIC);
	memcpy(t->remote, peer, 16);
	e = tunnel_tree_insert(t, &exposing);
	if (e != NULL) {
		if (!exposing) {
			logcrit("already exist (add_tunnel)\n");
			ISC_MAGIC_FREE(t, ISC_TUNNEL_MAGIC);
			free(t);
			return NULL;
		}
		ISC_MAGIC_FREE(t, ISC_TUNNEL_MAGIC);
		free(t);
		t = e;
	}
	t->mtu = tundefmtu;
	if (enable_msspatch)
		t->flags |= TUNMSSFLG;
	t->flags |= default_toobig;

	logdebug(1, "create tunnel: remote=%s, mtu=%u, mss=%s toobig=%s",
		 addr2str(AF_INET6, peer), t->mtu,
		 (t->flags & TUNMSSFLG) != 0 ? "on" : "off",
		 toobig2str(t));
	tuncnt++;
	trace_tunnel(t, "add");
	return t;
}

/* Add a standard tunnel entry (returns a pointer to the new tunnel,
   or NULL on failure */

struct tunnel *
add_stdtunnel(struct sess *ss, u_char *peer, u_char *src)
{
	struct tunnel *t;
	struct t_data *d;
	u_int fidx = 0;
	static u_int src_idx = 0;

	logdebug(10, "add_stdtunnel");

	if (src != NULL) {
		for (fidx = 0; fidx < poolcnt; fidx++)
			if (memcmp(pools[fidx]->addr, src, 4) == 0)
				break;
		if (fidx >= poolcnt) {
			sslogerr(ss,
				 "can't find pool %s\n",
				 addr2str(AF_INET, src));
			return NULL;
		}
	}

	d = (struct t_data *) malloc(sizeof(*d));
	if (d == NULL) {
		sslogerr(ss, "malloc(stdtunnel): %s\n", strerror(errno));
		return NULL;
	}
	t = add_tunnel(ss, peer);
	if (t == NULL) {
		free(d);
		return NULL;
	}
	memset(d, 0, sizeof(*d));
	t->tdata = d;
	if (src != NULL)
		t->srcidx = fidx;
	else {
		t->srcidx = src_idx;
		if (++src_idx == poolcnt)
			src_idx = 0;
	}
	return t;
}

/* Try a (standard) tunnel entry */

int
try_tunnel(struct sess *ss, u_char *peer, u_char *src)
{
	struct tunnel *t;

	t = tunnel_lookup(peer);
	if (t == NULL) {
		if (acl6(peer))
			t = add_stdtunnel(ss, peer, src);
		else
		 	sslogerr(ss, "acl6 failure for tunnel %s\n",
				 addr2str(AF_INET6, peer));
		if (t == NULL)
			return -1;
	} else if (t->flags & TUNNONAT)
		return -1;
	else if ((src != NULL) &&
		 (memcmp(pools[t->srcidx]->addr, src, 4) != 0)) {
		sslogerr(ss, "another pool for tunnel %s\n",
			 addr2str(AF_INET6, t->remote));
		return -1;
	}
	fprintf(ss->ssout, "tunnel %s %s\n",
		addr2str(AF_INET6, t->remote),
		addr2str(AF_INET, pools[t->srcidx]->addr));
	return 0;
}

/* Reload a (standard) tunnel entry */

int
reload_tunnel(struct sess *ss, u_char *peer, u_char *src)
{
	struct tunnel *t;

	t = tunnel_lookup(peer);
	if (t == NULL) {
		t = add_stdtunnel(ss, peer, src);
		if (t == NULL)
			return -1;
		return 0;
	}
	if (t->flags & TUNNONAT) {
		sslogerr(ss, "nonat tunnel[%s]\n", addr2str(AF_INET6, peer));
		return -1;
	}
	if (src == NULL)
		return 0;
	if (memcmp(pools[t->srcidx]->addr, src, 4) != 0) {
		sslogerr(ss, "tunnel[%s] mismatch: has %s wants %s\n",
			 addr2str(AF_INET6, peer),
			 addr2str(AF_INET, pools[t->srcidx]->addr),
			 addr2str(AF_INET, src));
		return -1;
	}
	return 0;
}

/* Set tunnel MTU */

int
set_tunnel_mtu(struct sess *ss, u_char *remote, u_int mtu, u_int force)
{
	struct tunnel *t;

	logdebug(10, "set_tunnel_mtu");

	t = tunnel_lookup(remote);
	if (t == NULL) {
		sslogerr(ss,
			 "set_tunnel_mtu: can't find tunnel %s\n",
			 addr2str(AF_INET6, remote));
		return -1;
	}
	if (mtu > IPMAXLEN)
		mtu = IPMAXLEN;
	else if (mtu < TUNMINMTU)
		mtu = TUNMINMTU;
	if (!force && (t->mtu < (u_short) mtu))
		return -1;
	t->mtu = (u_short) mtu;
	return 0;
}

/* Set tunnel flag */

int
set_tunnel_flag(struct sess *ss, u_char *remote, u_char flags, u_char mask)
{
	struct tunnel *t;
	u_char oflags;

	t = tunnel_lookup(remote);
	if (t == NULL) {
		sslogerr(ss,
			 "set_tunnel_flag: can't find tunnel %s\n",
			 addr2str(AF_INET6, remote));
		return -1;
	}
	oflags = t->flags;
	t->flags = (oflags & ~mask) | (flags & mask);
	return 0;
}

/*
 * Data structures
 *	debug
 */

void
print_hashes(FILE *s)
{
	u_int n, cnt;

	if (s == NULL)
		s = stdout;
	fprintf(s, "fragment: %d <= %u <= %d\n",
		MINFRAGHASH, fraghashsz, MAXFRAGHASH);
	cnt = 0;
	for (n = 0; n < fraghashsz; n++)
		if (fraghash[n] != NULL)
			cnt++;
	fprintf(s,
#if ULONG_MAX > 4294967295UL
		"\tfill %u hits %lu/%lu lookups %lu/%lu\n",
#else
		"\tfill %u hits %llu/%llu lookups %llu/%llu\n",
#endif
		cnt, pfhhits, tfhhits, pfhlookups, tfhlookups);
	fprintf(s, "nat: %d <= %u <= %d\n",
		MINNATHASH, nathashsz, MAXNATHASH);
	cnt = 0;
	for (n = 0; n < nathashsz; n++)
		if (nathash[n] != NULL)
			cnt++;
	fprintf(s,
#if ULONG_MAX > 4294967295UL
		"\tfill %u hits %lu/%lu lookups %lu/%lu\n",
#else
		"\tfill %u hits %llu/%llu lookups %llu/%llu\n",
#endif
		cnt, pnhhits, tnhhits, pnhlookups, tnhlookups);
	fprintf(s, "tunnel: %d <= %u <= %d\n",
		MINTUNHASH, tunhashsz, MAXTUNHASH);
	cnt = 0;
	for (n = 0; n < tunhashsz; n++)
		if (tunhash[n] != NULL)
			cnt++;
	fprintf(s,
#if ULONG_MAX > 4294967295UL
		"\tfill %u hits %lu/%lu lookups %lu/%lu\n",
#else
		"\tfill %u hits %llu/%llu lookups %llu/%llu\n",
#endif
		cnt, pthhits, tthhits, pthlookups, tthlookups);
}

/* statistics */

uint64_t
dropped(int what, int ipv)
{
	uint64_t accu = 0;

	if (ipv == 0) {
		if (what == 0) {
			accu += statsdropped[DR_BAD6];
			accu += statsdropped[DR_ACL6];
			accu += statsdropped[DR_NOTUN];
			accu += statsdropped[DR_ICMP6];
			accu += statsdropped[DR_F6CNT];
			accu += statsdropped[DR_F6TCNT];
			accu += statsdropped[DR_BADF6];
			accu += statsdropped[DR_F6TM];
		} else {
			accu += debugdropped[DR_BAD6];
			accu += debugdropped[DR_ACL6];
			accu += debugdropped[DR_NOTUN];
			accu += debugdropped[DR_ICMP6];
			accu += debugdropped[DR_F6CNT];
			accu += debugdropped[DR_F6TCNT];
			accu += debugdropped[DR_BADF6];
			accu += debugdropped[DR_F6TM];
		}
	} else {
		if (what == 0) {
			accu += statsdropped[DR_BADIN];
			accu += statsdropped[DR_INGRESS];
			accu += statsdropped[DR_NATCNT];
			accu += statsdropped[DR_NATRT];
			accu += statsdropped[DR_NEWNAT];
			accu += statsdropped[DR_ICMPIN];
			accu += statsdropped[DR_BADOUT];
			accu += statsdropped[DR_DSTOUT];
			accu += statsdropped[DR_ICMPOUT];
			accu += statsdropped[DR_NATOUT];
			accu += statsdropped[DR_TOOBIG];
			accu += statsdropped[DR_FINCNT];
			accu += statsdropped[DR_FINTCNT];
			accu += statsdropped[DR_FOUTCNT];
			accu += statsdropped[DR_BADF4];
			accu += statsdropped[DR_F4MEM];
			accu += statsdropped[DR_FINTM];
			accu += statsdropped[DR_FOUTTM];
		} else {
			accu += debugdropped[DR_BADIN];
			accu += debugdropped[DR_INGRESS];
			accu += debugdropped[DR_NATCNT];
			accu += debugdropped[DR_NATRT];
			accu += debugdropped[DR_NEWNAT];
			accu += debugdropped[DR_ICMPIN];
			accu += debugdropped[DR_BADOUT];
			accu += debugdropped[DR_DSTOUT];
			accu += debugdropped[DR_ICMPOUT];
			accu += debugdropped[DR_NATOUT];
			accu += debugdropped[DR_TOOBIG];
			accu += debugdropped[DR_FINCNT];
			accu += debugdropped[DR_FINTCNT];
			accu += debugdropped[DR_FOUTCNT];
			accu += debugdropped[DR_BADF4];
			accu += debugdropped[DR_F4MEM];
			accu += debugdropped[DR_FINTM];
			accu += debugdropped[DR_FOUTTM];
		}
	}
	return accu;
}

void
print_stats(FILE *s)
{
	if (s == NULL)
		s = stdout;
	fprintf(s, "tun=%u tcp=%u/%u udp=%u/%u other=%u/%u stat=%u prr=%u\n",
		tuncnt, natcntt, natcntt / poolcnt,
		natcntu, natcntu / poolcnt,
		natcnto , natcnto / poolcnt,
		snatcnt, prrcnt);
#if ULONG_MAX > 4294967295UL
	fprintf(s, "received: v6=%lu v4=%lu\n", statsrcv6, statsrcv4);
	fprintf(s, "sent: v6=%lu v4=%lu\n", statssent6, statssent4);
	fprintf(s, "dropped: v6=%lu v4=%lu\n",
		dropped(0, 0), dropped(0, 1));
	fprintf(s, "frag: in6[%u]=%lu/%lu in[%u]=%lu/%lu ",
		frags6cnt, statsfrgin6, statsreas6,
		fragsincnt, statsfrgin, statsreasin);
	fprintf(s, "frag: out[%u]=%lu/%lu out6=%lu\n",
		fragsoutcnt, statsfrout, statsreasout, statsfrgout6);
	fprintf(s, "in: nat=%lu prr=%lu nonat=%lu icmp6=%lu icmp4=%lu\n",
		statsnatin, statsprrin, statsnonatin,
		statsnaticmpin6, statsnaticmpin4);
	fprintf(s, "out: nat=%lu prr=%lu nonat=%lu icmp=%lu\n",
		statsnatout, statsprrout, statsnonatout, statsnaticmpout);
	fprintf(s, "tcpmss: seen=%lu patched=%lu toobig=%lu\n",
		statstcpmss, statsmsspatched, statstoobig);
	fprintf(s, "ftpalg: port=%lu eprt=%lu 227=%lu 229=%lu\n",
		statsftpport, statsftpeprt, statsftp227, statsftp229);
	fprintf(s, "nat: created=%lu deleted=%lu\n",
		statscnat, statsdnat);
	if (tunnel_debugged == NULL)
		goto rates;
	fprintf(s, "debug for %s\n",
		addr2str(AF_INET6, tunnel_debugged->remote));
	fprintf(s, " received: v6=%lu v4=%lu\n", debugrcv6, debugrcv4);
	fprintf(s, " sent: v6=%lu v4=%lu\n", debugsent6, debugsent4);
	fprintf(s, " dropped: v6=%lu v4=%lu\n",
		dropped(1, 0), dropped(1, 1));
	fprintf(s, " frag: in6[%u]=%lu/%lu in[%u]=%lu/%lu out6=%lu\n",
		tunnel_debugged->frg6cnt, debugfrgin6, debugreas6,
		tunnel_debugged->frg4cnt, debugfrgin, debugreasin,
		debugfrgout6);
	fprintf(s, " in: nat=%lu prr=%lu nonat=%lu icmp6=%lu icmp4=%lu\n",
		debugnatin, debugprrin, debugnonatin,
		debugnaticmpin6, debugnaticmpin4);
	fprintf(s, " out: nat=%lu prr=%lu nonat=%lu icmp=%lu\n",
		debugnatout, debugprrout, debugnonatout, debugnaticmpout);
	fprintf(s, " tcpmss: seen=%lu patched=%lu toobig=%lu\n",
		debugtcpmss, debugmsspatched, debugtoobig);
	fprintf(s, " ftpalg: port=%lu eprt=%lu 227=%lu 229=%lu\n",
		debugftpport, debugftpeprt, debugftp227, debugftp229);
	if (tunnel_debugged->flags & TUNNONAT)
		goto rates;
	fprintf(s, " nat[%u/%u/%u]: created=%lu deleted=%lu\n",
		tunnel_debugged->tnatcnt[0],
		tunnel_debugged->tnatcnt[1],
		tunnel_debugged->tnatcnt[2],
		debugcnat, debugdnat);
	fprintf(s, " nat rate: tcp=%u/%u udp=%u/%u icmp=%u/%u\n",
		tunnel_debugged->tnatrt[0], maxtnatrt[0],
		tunnel_debugged->tnatrt[1], maxtnatrt[1],
		tunnel_debugged->tnatrt[2], maxtnatrt[2]);
#else
	fprintf(s, "received: v6=%llu v4=%llu\n", statsrcv6, statsrcv4);
	fprintf(s, "sent: v6=%llu v4=%llu\n", statssent6, statssent4);
	fprintf(s, "dropped: v6=%llu v4=%llu\n",
		dropped(0, 0), dropped(0, 1));
	fprintf(s, "frag: in6[%u]=%llu/%llu in[%u]=%llu/%llu ",
		frags6cnt, statsfrgin6, statsreas6,
		fragsincnt, statsfrgin, statsreasin);
	fprintf(s, "frag: out[%u]=%llu/%llu out6=%llu\n",
		fragsoutcnt, statsfrout, statsreasout, statsfrgout6);
	fprintf(s, "in: nat=%llu prr=%llu nonat=%llu icmp6=%llu icmp4=%llu\n",
		statsnatin, statsprrin, statsnonatin,
		statsnaticmpin6, statsnaticmpin4);
	fprintf(s, "out: nat=%llu prr=%llu nonat=%llu icmp=%llu\n",
		statsnatout, statsprrout, statsnonatout, statsnaticmpout);
	fprintf(s, "tcpmss: seen=%llu patched=%llu toobig=%llu\n",
		statstcpmss, statsmsspatched, statstoobig);
	fprintf(s, "ftpalg: port=%llu eprt=%llu 227=%llu 229=%llu\n",
		statsftpport, statsftpeprt, statsftp227, statsftp229);
	fprintf(s, "nat: created=%llu deleted=%llu\n",
		statscnat, statsdnat);
	if (tunnel_debugged == NULL)
		goto rates;
	fprintf(s, "debug for %s\n",
		addr2str(AF_INET6, tunnel_debugged->remote));
	fprintf(s, " received: v6=%llu v4=%llu\n", debugrcv6, debugrcv4);
	fprintf(s, " sent: v6=%llu v4=%llu\n", debugsent6, debugsent4);
	fprintf(s, " dropped: v6=%llu v4=%llu\n",
		dropped(1, 0), dropped(1, 1));
	fprintf(s, " frag: in6[%u]=%llu/%llu in[%u]=%llu/%llu out6=%llu\n",
		tunnel_debugged->frg6cnt, debugfrgin6, debugreas6,
		tunnel_debugged->frg4cnt, debugfrgin, debugreasin,
		debugfrgout6);
	fprintf(s, " in: nat=%llu prr=%llu nonat=%llu icmp6=%llu icmp4=%llu\n",
		debugnatin, debugprrin, debugnonatin,
		debugnaticmpin6, debugnaticmpin4);
	fprintf(s, " out: nat=%llu prr=%llu nonat=%llu icmp=%llu\n",
		debugnatout, debugprrout, debugnonatout, debugnaticmpout);
	fprintf(s, " tcpmss: seen=%llu patched=%llu toobig=%llu\n",
		debugtcpmss, debugmsspatched, debugtoobig);
	fprintf(s, " ftpalg: port=%llu eprt=%llu 227=%llu 229=%llu\n",
		debugftpport, debugftpeprt, debugftp227, debugftp229);
	if (tunnel_debugged->flags & TUNNONAT)
		goto rates;
	fprintf(s, " nat[%u/%u/%u]: created=%llu deleted=%llu\n",
		tunnel_debugged->tnatcnt[0],
		tunnel_debugged->tnatcnt[1],
		tunnel_debugged->tnatcnt[2],
		debugcnat, debugdnat);
	fprintf(s, " nat rate: tcp=%u/%u udp=%u/%u icmp=%u/%u\n",
		tunnel_debugged->tnatrt[0], maxtnatrt[0],
		tunnel_debugged->tnatrt[1], maxtnatrt[1],
		tunnel_debugged->tnatrt[2], maxtnatrt[2]);
#endif
    rates:
	fprintf(s, "rates\n");
	fprintf(s, "received v6=%f %f %f\n",
		ratercv6[0], ratercv6[1], ratercv6[2]);
	fprintf(s, "received v4=%f %f %f\n",
		ratercv4[0], ratercv4[1], ratercv4[2]);
	fprintf(s, "sent v6=%f %f %f\n",
		ratesent6[0], ratesent6[1], ratesent6[2]);
	fprintf(s, "sent v4=%f %f %f\n",
		ratesent4[0], ratesent4[1], ratesent4[2]);
	fprintf(s, "nat created=%f %f %f\n",
		ratecnat[0], ratecnat[1], ratecnat[2]);
	fprintf(s, "nat deleted=%f %f %f\n",
		ratednat[0], ratednat[1], ratednat[2]);
}

void
print_dropped(FILE *s)
{
	int i;
	if (s == NULL)
		s = stdout;
#if ULONG_MAX > 4294967295UL
	fprintf(s, "summary: v6=%lu(%lu) v4=%lu(%lu)\n",
		dropped(0, 0), dropped(1, 0), dropped(0, 1), dropped(1, 1));
	for (i = 0; i <= DR_MAX; i++) {
		if ((statsdropped[i] != 0) || (debugdropped[i] != 0))
			fprintf(s, "\t%lu(%lu):\t%s\n",
				statsdropped[i], debugdropped[i],
				dropreason[i]);
	}
#else
	fprintf(s, "summary: v6=%llu(%llu) v4=%llu(%llu)\n",
		dropped(0, 0), dropped(1, 0), dropped(0, 1), dropped(1, 1));
	for (i = 0; i <= DR_MAX; i++) {
		if ((statsdropped[i] != 0) || (debugdropped[i] != 0))
			fprintf(s, "\t%llu(%llu):\t%s\n",
				statsdropped[i], debugdropped[i],
				dropreason[i]);
	}
#endif
}

/* fragments */

void
print_frag_elm(FILE *s, struct frag *p)
{
	if (s == NULL)
		s = stdout;
	fprintf(s, "addr=%lx next=%lx ", (u_long) p,
		(u_long) ISC_SLIST_NEXT(p, fragchain));
	fprintf(s, "buf=%lx len=%u off=%u\n",
		(u_long) p->buf, p->len, p->off);
}

void
print_frag(FILE *s, struct frag *f)
{
	struct frag *p;

	if (s == NULL)
		s = stdout;
	fprintf(s, "addr=%lx next=%lx ", (u_long) f,
		(u_long) ISC_TAILQ_NEXT(f, ffragchain));
	if (f->tunnel != NULL)
		fprintf(s, "tunnel=%s ",
			addr2str(AF_INET6, f->tunnel->remote));
	fprintf(s, "buf=%lx len=%u off=%u expire=%ld\n",
		(u_long) f->buf, f->len, f->off,
		(long) (f->expire - seconds));

	if (ISC_SLIST_FIRST(&f->fraglist) == NULL)
		return;
	fprintf(s, "Chain:\n");
	ISC_SLIST_FOREACH(p, &f->fraglist, fragchain) {
		fprintf(s, "\t");
		print_frag_elm(s, p);
	}
}

void
print_frags6(FILE *s)
{
	struct frag *f;
	int i = 0;

	if (s == NULL)
		s = stdout;
	ISC_TAILQ_FOREACH(f, &frags6, ffragchain) {
		fprintf(s, "%s%lx%s",
			(i & 3) != 0 ? " " : "",
			(u_long) f,
			(i & 3) == 3 ? "\n" : "");
		i++;
	}
	if ((i & 3) != 3)
		fprintf(s, "\n");
}

void
print_fragsin(FILE *s)
{
	struct frag *f;
	int i = 0;

	if (s == NULL)
		s = stdout;
	ISC_TAILQ_FOREACH(f, &fragsin, ffragchain) {
		fprintf(s, "%s%lx%s",
			(i & 3) != 0 ? " " : "",
			(u_long) f,
			(i & 3) == 3 ? "\n" : "");
		i++;
	}
	if ((i & 3) != 3)
		fprintf(s, "\n");
}

void
print_fragsout(FILE *s)
{
	struct frag *f;
	int i = 0;

	if (s == NULL)
		s = stdout;
	ISC_TAILQ_FOREACH(f, &fragsout, ffragchain) {
		fprintf(s, "%s%lx%s",
			(i & 3) != 0 ? " " : "",
			(u_long) f,
			(i & 3) == 3 ? "\n" : "");
		i++;
	}
	if ((i & 3) != 3)
		fprintf(s, "\n");
}

u_int
check_frags6(struct tunnel *t)
{
	struct frag *f;
	u_int cnt = 0;

	ISC_TAILQ_FOREACH(f, &frags6, ffragchain) {
		ISC_MAGIC_CHECK(f, ISC_FRAGMENT_MAGIC);
		if (f->tunnel == t) {
#ifdef SIGNSHDR
			struct frag *p;

			ISC_SLIST_FOREACH(p, &f->fraglist, fragchain)
				ISC_MAGIC_CHECK(p, ISC_FRAGMENT_MAGIC);
#endif
			cnt++;
		}
	}
	return cnt;
}

u_int
check_frags4(struct tunnel *t)
{
	struct frag *f;
	u_int cnt = 0;

	ISC_TAILQ_FOREACH(f, &fragsin, ffragchain) {
		ISC_MAGIC_CHECK(f, ISC_FRAGMENT_MAGIC);
		if (f->tunnel == t) {
#ifdef SIGNSHDR
			struct frag *p;

			ISC_SLIST_FOREACH(p, &f->fraglist, fragchain)
				ISC_MAGIC_CHECK(p, ISC_FRAGMENT_MAGIC);
#endif
			cnt++;
		}
	}
	return cnt;
}

/* NAT sources */

void
print_pools(FILE *s)
{
	struct pool *ns;
	u_int i;

	if (s == NULL)
		s = stdout;
	fprintf(s, "poolcnt=%u\tbucket size: tcp=%u udp=%u echo=%u\n",
		poolcnt, bucksize[TCPPR], bucksize[UDPPR], bucksize[ICMPPR]);
	for (i = 0; i < poolcnt; i++) {
		fprintf(s, "pool[%u]: ", i);
		ns = pools[i];
		if (ns == NULL) {
			fprintf(s, "NULL???\n");
			continue;
		}
		fprintf(s,
			"%s\n tcp=%u/%u udp=%u/%u echo=%u/%u\n",
			addr2str(AF_INET, ns->addr),
			ns->natcnt[0], ns->maxport[0] - ns->minport[0],
			ns->natcnt[1], ns->maxport[1] - ns->minport[1],
			ns->natcnt[2], ns->maxport[2] - ns->minport[2]);
	}
}

/* NAT entries */

void
print_nat(FILE *s, struct nat *n)
{
	u_int p;

	if (s == NULL)
		s = stdout;

	if (n->flags & ON_HOLD) {
		fprintf(s, "%lx held\n", (u_long) n);
		return;
	}
	fprintf(s, "addr=%lx ", (u_long) n);
	if (n->tunnel != NULL) {
		fprintf(s, "tunnel=%s ",
			addr2str(AF_INET6, n->tunnel->remote));
		fprintf(s, "tleft=%lx ", (u_long) n->tleft);
		fprintf(s, "tright=%lx ", (u_long) n->tright);
	}
	if (n->generation != 0)
		fprintf(s, "gen=%u ", n->generation);
	if (n->timeout != 0) {
		fprintf(s, "timeout=%ld ", (long) (n->timeout - seconds));
		fprintf(s, "lifetime=%u ", n->lifetime);
		fprintf(s, "heap=%u ", n->heap_index);
	}
	fprintf(s, "\n");
	p = n->sport[0] << 8;
	p |= n->sport[1];
	fprintf(s, "%d src=%s/%u -> ", (int) n->proto,
		addr2str(AF_INET, n->src), p);
	p = n->nport[0] << 8;
	p |= n->nport[1];
	fprintf(s, "%s/%u dst=", addr2str(AF_INET, n->nsrc), p);
	if (n->flags & ALL_DST) {
		if (n->flags & PRR_NULL)
			fprintf(s, "any PRR\n");
		else if (n->flags & FTP_DATA)
			fprintf(s, "%s/* (ftp data)\n",
				addr2str(AF_INET, n->dst));
		else
			fprintf(s, "*\n");
	} else {
		p = n->dport[0] << 8;
		p |= n->dport[1];
		fprintf(s, "%s/%u\n", addr2str(AF_INET, n->dst), p);
	}
	switch (n->proto) {
	case IPTCP:
		if (n->tcpst != TCP_DEFAULT)
			fprintf(s, "tcp status=%d\n", (int) n->tcpst);
		if (n->flags & ~ALL_FLAGS)
			fprintf(s, "flags=%d\n", (int) n->flags);
		break;
	case IPUDP:
		if (n->flags & ~ALL_FLAGS)
			fprintf(s, "flags=%d\n", (int) n->flags);
		break;
	case IPICMP:
		if (n->flags != MATCH_ICMP)
			fprintf(s, "flags=%d\n", (int) n->flags);
		break;
	default:
		fprintf(s, "flags=%d\n", (int) n->flags);
		break;
	}
	if (ISC_LIST_FIRST(&n->xlist) != NULL)
		fprintf(s, "xfirst=%lx ", (u_long) ISC_LIST_FIRST(&n->xlist));
	if (ISC_LIST_PREV(n, xchain) != NULL)
		fprintf(s, "xnext=%lx xprev=%lx ",
			(u_long) ISC_LIST_NEXT(n, xchain),
			(u_long) ISC_LIST_PREV(n, xchain));
	if (ISC_SLIST_FIRST(&n->ftpseq) != NULL)
		fprintf(s, "ftpseq=%lx(%d)",
			(u_long) ISC_SLIST_FIRST(&n->ftpseq),
			ISC_SLIST_FIRST(&n->ftpseq)->delta);
	if ((ISC_LIST_FIRST(&n->xlist) != NULL) ||
	    (ISC_LIST_PREV(n, xchain) != NULL) ||
	    (ISC_SLIST_FIRST(&n->ftpseq) != NULL))
		fprintf(s, "\n");
}

void
print_nat_tree_elm(FILE *s, struct nat *n)
{
	if (s == NULL)
		s = stdout;
	if (n == NULL) {
		fprintf(s, "root[]=%lx\n", (u_long) nat_tree);
		return;
	}
	fprintf(s, "%c ", n->color == RB_BLACK ? 'B' : 'R');
	fprintf(s, "%lx ", (u_long) n);
	if (n->left != NULL)
		fprintf(s, "left=%lx ", (u_long) n->left);
	if (n->right != NULL)
		fprintf(s, "right=%lx ", (u_long) n->right);
	if (n->parent != NULL)
		fprintf(s, "parent=%lx\n", (u_long) n->parent);
}

void
print_nat_tree_branch(FILE *s, struct nat *n)
{
	if (n == NULL)
		return;
	if (n->left != NULL) {
		if ((n->left->left != NULL) || (n->left->right != NULL)) {
			fprintf(s, "<");
			print_nat_tree_branch(s, n->left);
		}
		fprintf(s, "<");
		print_nat_tree_elm(s, n->left);
	}
	if (n->right != NULL) {
		if ((n->right->left != NULL) || (n->right->right != NULL)) {
			fprintf(s, ">");
		print_nat_tree_branch(s, n->right);
		}
		fprintf(s, ">");
		print_nat_tree_elm(s, n->right );
	}
}

void
print_nat_tree(FILE *s)
{
	u_char i;

	if (s == NULL)
		s = stdout;
	fprintf(s, "last generation %u\n", lastgen);
	for (i = 0; i < PRCNT; i++) {
		fprintf(s, "nat root[%u] at %lx\n", i, (u_long) nat_tree[i]);
		print_nat_tree_branch(s, nat_tree[i]);
		if (nat_tree[i] != NULL) {
			print_nat_tree_elm(s, nat_tree[i]);
			fprintf(s, "\n");
		}
	}
}

void
check_proto(struct nat *n, u_char pr)
{
	switch (pr) {
	case TCPPR:
		if (n->proto != IPTCP)
			logerr("bad proto (not tcp) at %lx\n", (u_long) n);
		break;
	case UDPPR:
		if (n->proto != IPUDP)
			logerr("bad proto (not udp) at %lx\n", (u_long) n);
		break;
	default:
		if (n->proto != IPICMP)
			logerr("bad proto (not icmp) at %lx\n", (u_long) n);
		break;
	}
}

u_int
check_nat_tree(struct tunnel *t, struct nat *n, u_char pr)
{
	u_int ret = 0;

	if (n == NULL)
		return 0;
	ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
	if (n->tunnel == t) {
		check_proto(n, pr);
		ret = 1;
	}
	ret += check_nat_tree(t, n->left, pr);
	ret += check_nat_tree(t, n->right, pr);
	return ret;
}

u_int
check_nat_session(struct nat *n)
{
	u_int ret = 0;

	if (n == NULL)
		return 0;
	ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
	if ((n->generation != 0) && (n->generation <= FIRSTGEN))
		ret = 1;
	ret += check_nat_session(n->left);
	ret += check_nat_session(n->right);
	return ret;
}

u_int
check_nat_pool(struct pool *ns, struct nat *n, u_char pr)
{
	u_int port, ret = 0;
	u_char *bm;

	if (n == NULL)
		return 0;
	ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
	if (memcmp(n->nsrc, ns->addr, 4) == 0) {
		check_proto(n, pr);
		port = n->nport[0] << 8;
		port |= n->nport[1];
		if ((port >= ns->minport[pr]) && (port <= ns->maxport[pr])) {
			ret = 1;
			port -= ns->minport[pr];
			bm = ns->freebm[pr];
			if (bm[port / 8] & (1 << (port % 8)))
				logerr("nat %lx uses a free port\n",
				       (u_long) n);
		}
	}
	ret += check_nat_pool(ns, n->left, pr);
	ret += check_nat_pool(ns, n->right, pr);
	return ret;
}

u_int
check_nat(u_char pr)
{
	struct nat *n, *x;
	struct tunnel *t;
	u_int cnt = 0;

	for (n = nat_tree_min(pr); n != NULL; n = nat_tree_next(n)) {
		cnt++;
		if (n->flags & ON_HOLD) {
			logerr("nat %lx on hold\n", (u_long) n);
			continue;
		}
		ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
		t = n->tunnel;
		if (t == NULL) {
			logerr("nat %lx has no tunnel\n", (u_long) n);
			continue;
		}
		ISC_MAGIC_CHECK(t, ISC_TUNNEL_MAGIC);
		t = tunnel_lookup(n->tunnel->remote);
		if (t == NULL) {
			logerr("can't find tunnel at %s for nat %lx\n",
			       addr2str(AF_INET6, n->tunnel->remote),
			       (u_long) n);
			continue;
		} else if (t != n->tunnel) {
			logerr("tunnel mismatch at %s for nat %lx\n",
			       addr2str(AF_INET6, n->tunnel->remote),
			       (u_long) n);
			continue;
		} else if (t->flags & TUNNONAT) {
			logerr("nat %lx on nonat %s\n",
			       (u_long) n,
			       addr2str(AF_INET6, t->remote));
			continue;
		}
		x = nat_splay_ro_find(pr, n, 1);
		if (x == NULL)
			logerr("can't find nat %lx in tunnel %s\n",
			       (u_long) n,
			       addr2str(AF_INET6, t->remote));
		else if (x != n)
			logerr("nat mismatch (%lx != %lx) in tunnel %s\n",
			       (u_long) n, (u_long) x,
			       addr2str(AF_INET6, t->remote));
	}
	return cnt;
}

void
check_nats(void)
{
	u_int cnt;

	cnt = check_nat(0);
	logdebug(10, "nat tree cnt[tcp]=%u", cnt);
	cnt = check_nat(1);
	logdebug(10, "nat tree cnt[udp]=%u", cnt);
	cnt = check_nat(2);
	logdebug(10, "nat tree cnt[icmp]=%u", cnt);
}

void
print_nat_splay_elm(FILE *s, struct nat *n)
{
	if (s == NULL)
		s = stdout;
	fprintf(s, "%lx", (u_long) n);
	if (n->tleft != NULL)
		fprintf(s, " tleft=%lx", (u_long) n->tleft);
	if (n->tright != NULL)
		fprintf(s, " tright=%lx", (u_long) n->tright);
	fprintf(s, "\n");
}

void
print_nat_splay_branch(FILE *s, struct nat *n)
{
	if (n == NULL)
		return;
	if (n->tleft != NULL) {
		fprintf(s, "<");
		print_nat_splay_branch(s, n->tleft);
	}
	print_nat_splay_elm(s, n);
	if (n->tright != NULL) {
		fprintf(s, ">");
		print_nat_splay_branch(s, n->tright);
	}
}

void
print_nat_splay(FILE *s, u_char *remote)
{
	struct tunnel *t;
	u_char i;

	if (s == NULL)
		s = stdout;
	t = tunnel_lookup(remote);
	if ((t == NULL) || (t->flags & TUNNONAT))
		return;
	for (i = 0; i < PRCNT; i++)
		if (t->tnat_root[i] != NULL) {
			fprintf(s, "nat splay root[%u] at %lx\n",
				i, (u_long) t->tnat_root[i]);
			print_nat_splay_branch(s, t->tnat_root[i]);
		}
}

void
print_nat_heap(FILE *s, u_int idx)
{
	if (s == NULL)
		s = stdout;
	if ((idx == 0) || (idx > nat_heap_last))
		fprintf(s, "heap: size=%u last=%u array=%lx\n",
			nat_heap_size, nat_heap_last, (u_long) nat_heap);
	else
		fprintf(s, "heap[%u]=%lx\n", idx, (u_long) nat_heap[idx]);
}

void
check_nat_splay_elm(struct tunnel *t, struct nat *n, u_char pr)
{
	struct nat *nn;

	ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
	check_proto(n, pr);
	if (n->tunnel != t)
		logerr("bad tunnel at %ls\n", (u_long) n);
	if (pr != TCPPR) {
		if (n->tcpst != TCP_DEFAULT)
			logerr("bad tcp state at %lx\n", (u_long) n);
		if (!ISC_SLIST_EMPTY(&n->ftpseq))
			logerr("bad ftp seq at %lx\n", (u_long) n);
	}
#ifdef SIGNSHDR
	else {
		struct ftpseq *fs;

		ISC_SLIST_FOREACH(fs, &n->ftpseq, chain)
			ISC_MAGIC_CHECK(fs, ISC_FTPSEQ_MAGIC);
	}
#endif
		
	nn = nat_tree_find_wild(pr, n);
	if (nn == NULL)
		logerr("can't find %lx in tree\n", (u_long) n);
	else if (nn != n)
		logerr("tree mismatch (%lx != %lx)\n",
		       (u_long) n, (u_long) nn);
}

u_int
check_nat_splay(struct tunnel *t, struct nat *n, u_char pr)
{
	u_int ret = 1;

	if (n == NULL)
		return 0;
	if (n->flags & ON_HOLD) {
		logerr("%lx on hold\n", (u_long) n);
		return 1;
	}
	check_nat_splay_elm(t, n, pr);
	ret += check_nat_splay(t, n->tleft, pr);
	ret += check_nat_splay(t, n->tright, pr);
	return ret;
}

u_int
check_helds(struct pool *ns, u_char pr)
{
	struct held *h;
	u_int port, i, cnt = 0;
	u_char *bm;

	ISC_TAILQ_FOREACH(h, &ns->helds[pr], chain) {
		if (h->flags != ON_HOLD) {
			logerr("bad on hold at %lx\n", (u_long) h);
			continue;
		}
		ISC_MAGIC_CHECK(h, ISC_HELD_MAGIC);
		port = h->nport[0] << 8;
		port |= h->nport[1];
		if ((port < ns->minport[pr]) ||
		    (port > ns->maxport[pr])) {
			logerr("on hold %lx port[%hhu] %u is out of range\n",
			       (u_long) h, pr, port);
			continue;
		}
		cnt++;
		i = port - ns->minport[pr];
		bm = ns->freebm[pr];
		if (bm[i / 8] & (1 << (i % 8)))
			logerr("on hold %lx port[%hhu] %u uses a free port\n",
			       (u_long) h, pr, port);
	}
	return cnt;
}

u_int
check_freebm(struct pool *ns, u_char pr)
{
	u_char *bm = ns->freebm[pr];
	u_int port, i, cnt = 0;

	for (port = ns->minport[pr]; port <= ns->maxport[pr]; port++) {
		i = port - ns->minport[pr];
		if (bm[i / 8] & (1 << (i % 8)))
			cnt++;
	}
	return cnt;
}

void
check_pool_elm(struct pool *ns, u_int *ncnt)
{
	u_int cnt0, cnt;
	u_char i;

	ISC_MAGIC_CHECK(ns, ISC_POOL_MAGIC);
	for (i = 0; i < PRCNT; i++) {
		cnt0 = check_nat_pool(ns, nat_tree[i], i);
		cnt = check_helds(ns, i);
		logdebug(10, "pool %s held cnt[%hhu]=%u",
			 addr2str(AF_INET, ns->addr), i, cnt);
		cnt += cnt0;
		if ((u_int) ns->natcnt[i] != cnt)
			logerr("pool %s cnt[%hhu] mismatch (%u != %u)\n",
			       addr2str(AF_INET, ns->addr),
			       i, (u_int) ns->natcnt[i], cnt);
		ncnt[i] += cnt0;
		cnt = check_freebm(ns, i);
		logdebug(10, "pool %s freebm[%hhu]=%u",
			 addr2str(AF_INET, ns->addr), i, cnt);
	}
}

void
check_pools(void)
{
	struct pool *ns;
	u_int i, cnt[PRCNT];

	for (i = 0; i < PRCNT; i++)
		cnt[i] = 0;
	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL) {
			logerr("pools[%u] is NULL\n", i);
			continue;
		}
		check_pool_elm(ns, cnt);
	}
	if (natcntt != cnt[TCPPR])
		logerr("TCP natcnt mismatch (%u != %u)\n",
		       natcntt, cnt[TCPPR]);
	if (natcntu != cnt[UDPPR])
		logerr("UDP natcnt mismatch (%u != %u)\n",
		       natcntu, cnt[UDPPR]);
	if (natcnto != cnt[ICMPPR])
		logerr("ICMP natcnt mismatch (%u != %u)\n",
		       natcnto, cnt[ICMPPR]);
}

/* tunnels */

void
print_tunnel_elm(FILE *s, struct tunnel *t)
{
	u_char i;

	if (t->flags & TUNNONAT) {
		fprintf(s, "nonat %s/%u (gen %u, next at %lx)\n",
			addr2str(AF_INET, t->nnaddr),
			t->nnplen,
			t->ngeneration,
			(u_long) ISC_STAILQ_NEXT(t, nchain));
		goto common;
	}
	fprintf(s, "src=%s ", addr2str(AF_INET, pools[t->srcidx]->addr));
	fprintf(s, "%u/%u/%u bucket\n",
		t->avail[0], t->avail[1], t->avail[2]);
	fprintf(s, "%u/%u/%u last %ld nat\n",
		t->tnatcnt[0], t->tnatcnt[1], t->tnatcnt[2],
		seconds - t->lastnat);
	for (i = 0; i < PRCNT; i++)
		if (t->tnat_root[i] != NULL)
			fprintf(s, "root[%u] nat at %lx\n",
				i, (u_long) t->tnat_root[i]);
    common:
	if (t->mtu != tundefmtu)
		fprintf(s, "mtu=%u ", (u_int) t->mtu);
	fprintf(s, "mss=%s toobig=%s%s\n",
		(t->flags & TUNMSSFLG) != 0 ? "on" : "off",
		toobig2str(t),
		(t->flags & TUNDEBUG) != 0 ? " debug=on" : "");
}

void
print_tunnel(FILE *s, u_char *remote)
{
	struct tunnel *t;

	if (s == NULL)
		s = stdout;
	t = tunnel_lookup(remote);
	if (t == NULL) {
		fprintf(s, "no tunnel at %s\n", addr2str(AF_INET6, remote));
		return;
	}
	print_tunnel_elm(s, t);
}

void
print_tunnel_tree_elm(FILE *s, struct tunnel *t)
{
	if (s == NULL)
		s = stdout;
	if (t == NULL) {
		fprintf(s, "root=%lx\n", (u_long) tunnel_tree);
		return;
	}
	fprintf(s, "%lx ", (u_long) t);
	if ((t->flags & TUNGLUE) != 0) {
		fprintf(s, "bit=%u ", t->bit);
		fprintf(s, "parent=%lx ", (u_long) t->parent);
		if (t->left != NULL)
			fprintf(s, "left=%lx ", (u_long) t->left);
		if (t->right != NULL)
			fprintf(s, "right=%lx", (u_long) t->right);
		fprintf(s, "\n");
	} else {
		fprintf(s, "%s\n", addr2str(AF_INET6, t->remote));
		fprintf(s, "parent=%lx\n", (u_long) t->parent);
		if (t->left != NULL)
			fprintf(s, "left?=%lx\n", (u_long) t->left);
		if (t->right != NULL)
			fprintf(s, "right?=%lx\n", (u_long) t->right);
	}
}

void
print_tunnel_tree_branch(FILE *s, struct tunnel *t)
{
	if (t == NULL)
		return;
	if (t->left != NULL) {
		if ((t->left->left != NULL) || (t->left->right != NULL)) {
			fprintf(s, "<");
			print_tunnel_tree_branch(s, t->left);
		}
		fprintf(s, "<");
		print_tunnel_tree_elm(s, t->left);
	}
	if (t->right != NULL) {
		if ((t->right->left != NULL) || (t->right->right != NULL)) {
			fprintf(s, ">");
			print_tunnel_tree_branch(s, t->right);
		}
		fprintf(s, ">");
		print_tunnel_tree_elm(s, t->right);
	}
}

void
print_tunnel_tree(FILE *s)
{
	if (s == NULL)
		s = stdout;
	fprintf(s, "tunnel root at %lx\n", (u_long) tunnel_tree);
	if (tunnel_debugged != NULL)
		fprintf(s, "debugged tunnel at %lx\n",
			(u_long) tunnel_debugged);
	print_tunnel_tree_branch(s, tunnel_tree);
	if (tunnel_tree != NULL)
		print_tunnel_tree_elm(s, tunnel_tree);
}

void
print_nonats(FILE *s)
{
	struct tunnel *t;

	if (s == NULL)
		s = stdout;
	ISC_STAILQ_FOREACH(t, &nonats, nchain)
		print_tunnel_elm(s, t);
}

u_int
check_tunnel_elm(struct tunnel *t, u_int *f6cnt, u_int *f4cnt)
{
	u_int cnt, ret = 0;
	u_char i;

	ISC_MAGIC_CHECK(t, ISC_TUNNEL_MAGIC);
	cnt = check_frags6(t);
	if ((u_int) t->frg6cnt != cnt)
		logerr("bad frg6cnt (%u != %u) for tunnel %s\n",
		       (u_int) t->frg6cnt, cnt,
		       addr2str(AF_INET6, t->remote));
	(*f6cnt) += cnt;
	cnt = check_frags4(t);
	if ((u_int) t->frg4cnt != cnt)
		logerr("bad frg4cnt (%u != %u) for tunnel %s\n",
		       (u_int) t->frg4cnt, cnt,
		       addr2str(AF_INET6, t->remote));
	(*f4cnt) += cnt;
	for (i = 0; i < PRCNT; i++) {
		if (t->tnat_root[i] == NULL) {
			if (t->tnatcnt[i] != 0)
				logerr("bad zero natcnt[%hhu]=%hu for %s\n",
				       i, t->tnatcnt[i],
				       addr2str(AF_INET6, t->remote));
			continue;
		}
		cnt = check_nat_splay(t, t->tnat_root[i], i);
		if ((u_int) t->tnatcnt[i] != cnt)
			logerr("bad natcnt[%hhu] (%u != %u) for %s\n",
			       i, (u_int) t->tnatcnt[i], cnt,
			       addr2str(AF_INET6, t->remote));
		ret += cnt;
		cnt = check_nat_tree(t, nat_tree[i], i);
		if ((u_int) t->tnatcnt[i] != cnt)
			logerr("bad tree natcnt[%hhu] (%u != %u) for %s\n",
			       i, (u_int) t->tnatcnt[i], cnt,
			       addr2str(AF_INET6, t->remote));
	}		
	return ret;
}

void
check_nonat_elm(struct tunnel *t, u_int *f6cnt, u_int *f4cnt)
{
	struct tunnel *x;
	u_int cnt;

	ISC_MAGIC_CHECK(t, ISC_TUNNEL_MAGIC);
	cnt = check_frags6(t);
	if ((u_int) t->frg6cnt != cnt)
		logerr("bad frg6cnt (%u != %u) for nonat %s\n",
		       (u_int) t->frg6cnt, cnt,
		       addr2str(AF_INET6, t->remote));
	(*f6cnt) += cnt;
	cnt = check_frags4(t);
	if ((u_int) t->frg4cnt != cnt)
		logerr("bad frg4cnt (%u != %u) for nonat %s\n",
		       (u_int) t->frg4cnt, cnt,
		       addr2str(AF_INET6, t->remote));
	(*f4cnt) += cnt;
	cnt = 0;
	ISC_STAILQ_FOREACH(x, &nonats, nchain)
		if (x == t)
			cnt++;
	if (cnt == 0)
		logerr("can't find nonat %s\n",
		       addr2str(AF_INET6, t->remote));
	else if (cnt > 1)
		logerr("multiple (%u) nonat %s\n", cnt,
		       addr2str(AF_INET6, t->remote));
}

u_int
check_tunnel_branch(struct tunnel *t, u_int *f6cnt, u_int *f4cnt, u_int *ncnt)
{
	u_int ret = 0;

	if (t == NULL)
		return 0;
	if ((t->flags & TUNGLUE) == 0) {
		if (t->flags & TUNNONAT)
			check_nonat_elm(t, f6cnt, f4cnt);
		else
			(*ncnt) += check_tunnel_elm(t, f6cnt, f4cnt);
		ret = 1;
	}	  
	ret += check_tunnel_branch(t->left, f6cnt, f4cnt, ncnt);
	ret += check_tunnel_branch(t->right, f6cnt, f4cnt, ncnt);
	return ret;
}

void
check_tunnels(void)
{
	u_int cnt, f6cnt = 0, f4cnt = 0, ncnt = 0;

	cnt = check_tunnel_branch(tunnel_tree, &f6cnt, &f4cnt, &ncnt);
	if (tuncnt != cnt)
		logerr("tunnel count mismatch (%u != %u)\n",
		       tuncnt, cnt);
	if (frags6cnt != f6cnt)
		logerr("fragments IPv6 count mismatch (%u != %u)\n",
		       frags6cnt, f6cnt);
	if (fragsincnt != f4cnt)
		logerr("fragments IPv4 count mismatch (%u != %u)\n",
		       fragsincnt, f4cnt);
	cnt = natcntt + natcntu + natcnto + snatcnt + prrcnt;
	if (cnt != ncnt)
		logerr("total nat count mismatch (%u != %u)\n",
		       cnt, ncnt);
}

void
check_nonats(void)
{
	struct tunnel *t, *x;

	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		ISC_MAGIC_CHECK(t, ISC_TUNNEL_MAGIC);
		x = tunnel_lookup(t->remote);
		if (x == NULL)
			logerr("can't find nonat %s in tree\n",
			       addr2str(AF_INET6, t->remote));
		else if (x != t)
			logerr("nonat tree mismatch for %s\n",
			       addr2str(AF_INET6, t->remote));
	}
}

/* sessions */

void
print_sessions(FILE *s)
{
	struct sess *ss;
	u_int stdio_cnt = 0, unix_cnt = 0, tcp4_cnt = 0, tcp6_cnt = 0;

	if (s == NULL)
		s = stdout;
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		if (ss->sstype == &ccstdio)
			stdio_cnt++;
		else if (ss->sstype == &ccunix)
			unix_cnt++;
		else if (ss->sstype == &cctcp4)
			tcp4_cnt++;
		else if (ss->sstype == &cctcp6)
			tcp6_cnt++;
		else
			sslogerr(ss, "unknown session type\n");
	}
	fprintf(s, "stdio[%u] unix[%u] tcp4[%u] tcp6[%u] nextgen %u\n",
		stdio_cnt, unix_cnt, tcp4_cnt, tcp6_cnt, sesgen);
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		if (ss->name == NULL)
			fprintf(s, "session[%u]\n", ss->generation);
		else
			fprintf(s, "session[%u]=\"%s\"\n",
				ss->generation, ss->name);
	}
}

int
check_session_elm(struct sess *ss, int active)
{
	struct nat *n, *nn;
	u_int cnt = 0;
	u_char pr;

	ISC_MAGIC_CHECK(ss, ISC_SESSION_MAGIC);
	ISC_LIST_FOREACH(n, &ss->snats, gchain) {
		ISC_MAGIC_CHECK(n, ISC_NAT_MAGIC);
		if (active) {
			if (n->generation != ss->generation)
				logerr("session nat %lx generation mismatch\n",
				       (u_long) n);
			else
				cnt++;
		} else {
			if (n->generation != FIRSTGEN)
				logerr("session nat %lx generation mismatch\n",
				       (u_long) n);
			else
				cnt++;
		}
		switch (n->proto) {
		case IPTCP:
			pr = TCPPR;
			break;
		case IPUDP:
			pr = UDPPR;
			break;
		default:
			pr = ICMPPR;
			break;
		}
		nn = nat_tree_find_wild(pr, n);
		if (nn == NULL)
			logerr("can't find session nat %lx in tree\n",
			       (u_long) n);
		else if (nn != n)
			logerr("session nat tree mismatch (%lx != %lx)\n",
			       (u_long) n, (u_long) nn);
	}
	return cnt;
}

void
check_sessions(void)
{
	struct sess *ss;
	u_int scnt = 0, tcnt = 0;
	u_char i;

	ISC_LIST_FOREACH(ss, &sslist, chain)
		scnt += check_session_elm(ss, 1);
	ISC_LIST_FOREACH(ss, &orphans, chain)
		scnt += check_session_elm(ss, 0);
	for (i = 0; i < PRCNT; i++)
		tcnt += check_nat_session(nat_tree[i]);
	if (scnt != tcnt)
		logerr("session natcnt mismatch (%u != %u)\n", scnt, tcnt);
}

/*
 * Data structures
 *	commands
 */

/* Add an IPv6 ACL entry (if it doesn't already exist) */

int
add_acl6(struct sess *ss, u_char *addr, u_int plen)
{
	struct acl6 *a;

	ISC_STAILQ_FOREACH(a, &acl6s, chain) {
		ISC_MAGIC_CHECK(a, ISC_ACL6_MAGIC);
		if ((memcmp(a->addr, addr, 16) == 0) &&
		    (memcmp(a->mask, mask6[plen], 16) == 0))
			return 0;
	}
	a = (struct acl6 *) malloc(sizeof(*a));
	if (a == NULL) {
		sslogerr(ss, "malloc(acl6): %s\n", strerror(errno));
		return -1;
	}
	memset(a, 0, sizeof(*a));
	ISC_MAGIC_SET(a, ISC_ACL6_MAGIC);
	memcpy(a->addr, addr, 16);
	memcpy(a->mask, mask6[plen], 16);
	ISC_STAILQ_INSERT_TAIL(&acl6s, a, chain);
	return 0;
}

/* Add an IPv4 ACL entry (aka private, if doesn't already exit) */

int
add_private(struct sess *ss, u_char *addr, u_int plen)
{
	struct acl4 *a;

	ISC_STAILQ_FOREACH(a, &acl4s, chain) {
		ISC_MAGIC_CHECK(a, ISC_ACL4_MAGIC);
		if ((memcmp(a->addr, addr, 4) == 0) &&
		    (memcmp(a->mask, mask4[plen], 4) == 0))
			return 0;
	}
	a = (struct acl4 *) malloc(sizeof(*a));
	if (a == NULL) {
		sslogerr(ss, "malloc(acl4): %s\n", strerror(errno));
		return -1;
	}
	memset(a, 0, sizeof(*a));
	ISC_MAGIC_SET(a, ISC_ACL4_MAGIC);
	memcpy(a->addr, addr, 4);
	memcpy(a->mask, mask4[plen], 4);
	ISC_STAILQ_INSERT_TAIL(&acl4s, a, chain);
	return 0;
}

/* Add an IPv4 source for NAT */

int
add_pool(struct sess *ss, u_char *addr)
{
	struct pool **nv, *ns;
	u_char *bm;
	u_int pr, sz, bn, i;

	nv = (struct pool **) malloc((poolcnt + 1) * sizeof(*nv));
	if (nv == NULL) {
		sslogerr(ss, "malloc(pools): %s\n", strerror(errno));
		return -1;
	}
	if (pools != NULL) {
		memcpy(nv, pools, poolcnt * sizeof(*nv));
		free(pools);
	}
	pools = nv;

	ns = (struct pool *) malloc(sizeof(*ns));
	if (ns == NULL) {
		sslogerr(ss, "malloc(pool): %s\n", strerror(errno));
		return -1;
	}
	memset(ns, 0, sizeof(*ns));
	ISC_MAGIC_SET(ns, ISC_POOL_MAGIC);
	memcpy(ns->addr, addr, 4);
	ns->minport[TCPPR] = poolmin[TCPPR];
	ns->minport[UDPPR] = poolmin[UDPPR];
	ns->minport[ICMPPR] = poolmin[ICMPPR];
	ns->maxport[TCPPR] = poolmax[TCPPR];
	ns->maxport[UDPPR] = poolmax[UDPPR];
	ns->maxport[ICMPPR] = poolmax[ICMPPR];

	for (pr = 0; pr < PRCNT; pr++) {
		ISC_TAILQ_INIT(&ns->helds[pr]);
		sz = (ns->maxport[pr] - ns->minport[pr]) / 8;
		bm = (u_char *) malloc(sz + 1);
		if (bm == NULL) {
			sslogerr(ss,
				 "malloc(freebm): %s\n",
				 strerror(errno));
			while (pr-- >= 1)
				free(ns->freebm[pr]);
			ISC_MAGIC_FREE(ns, ISC_POOL_MAGIC);
			free(ns);
			return -1;
		}
		memset(bm, 0xff, sz);
		bm[sz] = 0;
		bn = (ns->maxport[pr] - ns->minport[pr]) % 8;
		for (i = 0; i <= bn; i++)
			bm[sz] |= 1 << i;
		ns->freebm[pr] = bm;
	}

	nv[poolcnt++] = ns;
	return 0;
}

/* Limit port range in an IPv4 source for NAT */

int
limit_port(struct sess *ss, u_char *addr, u_int proto,
	   u_int minport, u_int maxport)
{
	struct pool *ns;
	u_int i, sz, bn;
	u_char pr, *bm;

	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		if (memcmp(ns->addr, addr, 4) == 0)
			goto found;
	}
	/* not found: create it */
	if (add_pool(ss, addr) != 0)
		return -1;
	ns = pools[poolcnt - 1];
	if ((ns == NULL) || (memcmp(ns->addr, addr, 4) != 0)) {
		logcrit("can't create pool for %s\n",
			addr2str(AF_INET, addr));
		return -1;
	}

    found:
	switch (proto) {
	case IPTCP:
		pr = TCPPR;
		break;
	case IPUDP:
		pr = UDPPR;
		break;
	default:
		pr = ICMPPR;
		break;
	}
	ns->minport[pr] = minport;
	ns->maxport[pr] = maxport;

	if (ns->freebm[pr] != NULL)
		free(ns->freebm[pr]);
	ns->freebm[pr] = NULL;
	sz = (maxport - minport) / 8;
	bm = (u_char *) malloc(sz + 1);
	if (bm == NULL) {
		sslogerr(ss, "malloc(freebm): %s\n", strerror(errno));
		while (pr-- >= 1)
			free(ns->freebm[pr]);
		if (ns == pools[poolcnt - 1]) {
			poolcnt--;
			pools[poolcnt] = NULL;
		} else if (ns == pools[i])
			pools[i] = NULL;
		else {
			logcrit("lost pool on alloc failure\n");
			exit(1);
		}
		ISC_MAGIC_FREE(ns, ISC_POOL_MAGIC);
		free(ns);
		return -1;
	}
	memset(bm, 0xff, sz);
	bm[sz] = 0;
	bn = (maxport - minport) % 8;
	for (i = 0; i <= bn; i++)
		bm[sz] |= 1 << i;
	ns->freebm[pr] = bm;
	return 0;
}

/* Add a static NAT entry */

struct nat *
add_snat0(struct sess *ss,
	  u_char *src6, u_int proto,
	  u_char *src, u_char *sport,
	  u_char *nsrc, u_char *nport)
{
	struct nat *n;
	struct tunnel *t;
	struct pool *ns;
	u_int i;
	u_short np;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		if (memcmp(ns->addr, nsrc, 4) == 0)
			goto found;
	}
	sslogerr(ss, "can't find pool for %s\n", addr2str(AF_INET, nsrc));
	return NULL;

found:
	np = nport[0] << 8;
	np |= nport[1];
	if ((np >= ns->minport[pr]) && (np <= ns->maxport[pr])) {
		sslogerr(ss, "dynamic port %hu\n", np);
		return NULL;
	}

	t = tunnel_lookup(src6);
	if (t == NULL) {
		t = add_stdtunnel(ss, src6, nsrc);
		if (t == NULL)
			return NULL;
	}
	if (t->flags & TUNNONAT)
		return NULL;
	n = (struct nat *) malloc(sizeof(*n));
	if (n == NULL) {
		sslogerr(ss, "malloc(snat): %s\n", strerror(errno));
		return NULL;
	}
	memset(n, 0, sizeof(*n));
	ISC_MAGIC_SET(n, ISC_NAT_MAGIC);
	n->tunnel = t;
	n->generation = curgen;
	n->proto = proto;
	n->flags = ALL_DST | MATCH_PORT;
	memcpy(n->src, src, 4);
	memcpy(n->nsrc, nsrc, 4);
	memcpy(n->sport, sport, 2);
	memcpy(n->nport, nport, 2);
	if (nat_tree_insert(pr, n) != NULL) {
		logcrit("rb-collision(snat)\n");
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return NULL;
	}
	if (nat_splay_insert(pr, n) != NULL) {
		logcrit("splay-collision(snat)\n");
		(void) nat_tree_remove(pr, n);
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return NULL;
	}
	if (curgen < FIRSTGEN)
		ISC_LIST_INSERT_HEAD(&ss->snats, n, gchain);
	else
		ISC_LIST_INSERT_HEAD(&confnats, n, gchain);
	snatcnt++;
	t->tnatcnt[pr]++;
	statscnat++;
	if (t->flags & TUNDEBUG)
		debugcnat++;
#ifdef TRACE_NAT
	trace_nat(n, "add");
#endif
	return n;
}

int
add_snat(struct sess *ss,
	 u_char *src6, u_int proto,
	 u_char *src, u_char *sport,
	 u_char *nsrc, u_char *nport)
{
	struct nat *n;

	n = add_snat0(ss, src6, proto, src, sport, nsrc, nport);
	if (n == NULL)
		return -1;
	return 0;
}

/* Try a static NAT entry (check IPv4 addresses) */

struct nat *
try_snat(struct sess *ss,
	 u_char *src6, u_int proto,
	 u_char *src, u_char *sport,
	 u_char *nsrc, u_char *nport)
{
	struct nat *n, nat0;
	struct tunnel *t;
	u_char pr;

	if (!acl4(src)) {
		sslogerr(ss, "%s is not private\n",
			 addr2str(AF_INET, src));
		return NULL;
	}
	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	t = tunnel_lookup(src6);
	if (t == NULL) {
		sslogerr(ss, "can't find tunnel %s\n",
			 addr2str(AF_INET6, src6));
		return NULL;
	} else if (t->flags & TUNNONAT) {
		sslogerr(ss, "nonat tunnel %s\n",
			 addr2str(AF_INET6, src6));
		return NULL;
	} else if (memcmp(nsrc, pools[t->srcidx]->addr, 4) != 0) {
		sslogerr(ss, "bad natted source %s\n",
			 addr2str(AF_INET, nsrc));
		return NULL;
	}
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = proto;
	nat0.flags = ALL_DST | MATCH_PORT;
	memcpy(nat0.src, src, 4);
	memcpy(nat0.nsrc, nsrc, 4);
	memcpy(nat0.sport, sport, 2);
	memcpy(nat0.nport, nport, 2);
	n = nat_splay_find(pr, &nat0, 1, 1);
	if (n == NULL)
		return add_snat0(ss, src6, proto, src, sport, nsrc, nport);
	if (nat_tree_compare_all(n, &nat0) != 0) {
		sslogerr(ss, "collision in try_snat\n");
		return NULL;
	}
	return n;
}

/* Reload a static NAT entry */

int
reload_snat(struct sess *ss,
	    u_char *src6, u_int proto,
	    u_char *src, u_char *sport,
	    u_char *nsrc, u_char *nport)
{
	struct nat *n, nat0;
	struct tunnel *t;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	t = tunnel_lookup(src6);
	if (t == NULL)
		return add_snat(ss, src6, proto, src, sport, nsrc, nport);
	if (t->flags & TUNNONAT) {
		sslogerr(ss, "reload_snat: nonat\n");
		return -1;
	}
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = proto;
	nat0.flags = ALL_DST | MATCH_PORT;
	memcpy(nat0.src, src, 4);
	memcpy(nat0.nsrc, nsrc, 4);
	memcpy(nat0.sport, sport, 2);
	memcpy(nat0.nport, nport, 2);
	n = nat_splay_find(pr, &nat0, 1, 1);
	if (n == NULL)
		return add_snat(ss, src6, proto, src, sport, nsrc, nport);
	if (nat_tree_compare_all(n, &nat0) != 0) {
		sslogerr(ss, "collision in reload_snat\n");
		return -1;
	}
	if (n->generation <= FIRSTGEN) {
		if (ISC_LIST_PREV(n, gchain) != NULL)
			ISC_LIST_REMOVE(n, gchain);
		ISC_LIST_INSERT_HEAD(&confnats, n, gchain);
	}
	n->generation = curgen;
	return 0;
}

/* Add a A+P/PRR null NAT entry */

int
add_prr(struct sess *ss, u_char *src6, u_int proto, u_char *src, u_char *sport)
{
	struct nat *n;
	struct tunnel *t;
	struct pool *ns;
	u_int i;
	u_short np;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		if (memcmp(ns->addr, src, 4) == 0)
			goto found;
	}
	sslogerr(ss, "can't find pool for %s\n", addr2str(AF_INET, src));
	return -1;

found:
	np = sport[0] << 8;
	np |= sport[1];
	if ((np >= ns->minport[pr]) && (np <= ns->maxport[pr])) {
		sslogerr(ss, "dynamic port %hu\n", np);
		return -1;
	}

	t = tunnel_lookup(src6);
	if (t == NULL) {
		t = add_stdtunnel(ss, src6, NULL);
		if (t == NULL)
			return -1;
	} else if (t->flags & TUNNONAT)
		return -1;
	n = (struct nat *) malloc(sizeof(*n));
	if (n == NULL) {
		sslogerr(ss, "malloc(prr): %s\n", strerror(errno));
		return -1;
	}
	memset(n, 0, sizeof(*n));
	ISC_MAGIC_SET(n, ISC_NAT_MAGIC);
	n->tunnel = t;
	n->generation = curgen;
	n->proto = proto;
	n->flags = ALL_DST | PRR_NULL | MATCH_PORT;
	memcpy(n->src, src, 4);
	memcpy(n->nsrc, src, 4);
	memcpy(n->sport, sport, 2);
	memcpy(n->nport, sport, 2);
	if (nat_tree_insert(pr, n) != NULL) {
		logcrit("rb-collision(prr)\n");
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return -1;
	}
	if (nat_splay_insert(pr, n) != NULL) {
		logcrit("splay-collision(prr)\n");
		(void) nat_tree_remove(pr, n);
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return -1;
	}
	if (curgen < FIRSTGEN)
		ISC_LIST_INSERT_HEAD(&ss->snats, n, gchain);
	else
		ISC_LIST_INSERT_HEAD(&confnats, n, gchain);
	prrcnt++;
	t->tnatcnt[pr]++;
	statscnat++;
	if (t->flags & TUNDEBUG)
		debugcnat++;
#ifdef TRACE_NAT
	trace_nat(n, "add");
#endif
	return 0;
}

/* Reload a A+P/PRR null NAT entry */

int
reload_prr(struct sess *ss,
	   u_char *src6, u_int proto,
	   u_char *src, u_char *sport)
{
	struct nat *n, nat0;
	struct tunnel *t;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	t = tunnel_lookup(src6);
	if (t == NULL)
		return add_prr(ss, src6, proto, src, sport);
	if (t->flags & TUNNONAT) {
		sslogerr(ss, "reload_prr: nonat\n");
		return -1;
	}
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = proto;
	nat0.flags = ALL_DST | PRR_NULL | MATCH_PORT;
	memcpy(nat0.src, src, 4);
	memcpy(nat0.nsrc, src, 4);
	memcpy(nat0.sport, sport, 2);
	memcpy(nat0.nport, sport, 2);
	n = nat_splay_find(pr, &nat0, 1, 1);
	if (n == NULL)
		return add_prr(ss, src6, proto, src, sport);
	if (nat_tree_compare_all(n, &nat0) != 0) {
		sslogerr(ss, "collision in reload_prr\n");
		return -1;
	}
	if (n->generation <= FIRSTGEN) {
		if (ISC_LIST_PREV(n, gchain) != NULL)
			ISC_LIST_REMOVE(n, gchain);
		ISC_LIST_INSERT_HEAD(&confnats, n, gchain);
	}
	n->generation = curgen;
	return 0;
}

/* Add a no-nat entry */

int
add_nonat(struct sess *ss, u_char *peer, u_char *addr, u_int plen)
{
	struct tunnel *t;
	struct nn_data *n;

	n = (struct nn_data *) malloc(sizeof(*n));
	if (n == NULL) {
		sslogerr(ss, "malloc(nonat): %s\n", strerror(errno));
		return -1;
	}
	t = add_tunnel(ss, peer);
	if (t == NULL) {
		free(n);
		return -1;
	}
	memset(n, 0, sizeof(*n));
	t->nndata = n;
	t->flags |= TUNNONAT;
	t->ngeneration = curgen;
	memcpy(t->nnaddr, addr, 4);
	t->nnplen = plen;
	ISC_STAILQ_INSERT_TAIL(&nonats, t, nchain);
	return 0;
}

/* Reload a no-nat entry */

int
reload_nonat(struct sess *ss, u_char *peer, u_char *addr, u_int plen)
{
	struct tunnel *t, *x;

	t = tunnel_lookup(peer);
	if (t == NULL)
		return add_nonat(ss, peer, addr, plen);
	ISC_STAILQ_FOREACH(x, &nonats, nchain)
		if (x == t)
			break;
	if (x == NULL) {
		sslogerr(ss, "collision in reload_nonat\n");
		return -1;
	}
	t->ngeneration = curgen;
	return 0;
}

/* Delete an IPv6 ACL entry */

int
del_acl6(struct sess *ss, u_char *addr)
{
	struct acl6 *a;

	if (ISC_STAILQ_EMPTY(&acl6s)) {
		sslogerr(ss, "IPv6 ACL list is empty\n");
		return -1;
	}
	ISC_STAILQ_FOREACH(a, &acl6s, chain) {
		ISC_MAGIC_CHECK(a, ISC_ACL6_MAGIC);
		if (memcmp(a->addr, addr, 16) == 0)
			break;
	}
	if (a == NULL) {
		sslogerr(ss,
			 "can't find IPv6 ACL for %s\n",
			 addr2str(AF_INET6, addr));
		return -1;
	}
	ISC_STAILQ_REMOVE(&acl6s, a, acl6, chain);
	ISC_MAGIC_FREE(a, ISC_ACL6_MAGIC);
	free(a);
	return 0;
}

/* Delete an IPv4 ACL entry */

int
del_private(struct sess *ss, u_char *addr)
{
	struct acl4 *a;

	if (ISC_STAILQ_EMPTY(&acl4s)) {
		sslogerr(ss, "IPv4 ACL list is empty\n");
		return -1;
	}
	ISC_STAILQ_FOREACH(a, &acl4s, chain) {
		ISC_MAGIC_CHECK(a, ISC_ACL4_MAGIC);
		if (memcmp(a->addr, addr, 4) == 0)
			break;
	}
	if (a == NULL) {
		sslogerr(ss,
			 "can't find IPv4 ACL for %s\n",
			 addr2str(AF_INET, addr));
		return -1;
	}
	ISC_STAILQ_REMOVE(&acl4s, a, acl4, chain);
	ISC_MAGIC_FREE(a, ISC_ACL4_MAGIC);
	free(a);
	return 0;
}

/* Delete static NAT entry */

int
del_snat(struct sess *ss,
	 u_char *src6,
	 u_int proto,
	 u_char *src,
	 u_char *sport)
{
	struct nat nat0, *n;
	struct tunnel *t;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	t = tunnel_lookup(src6);
	if (t == NULL) {
		sslogerr(ss, "no tunnel %s\n", addr2str(AF_INET6, src6));
		return -1;
	} else if (t->flags & TUNNONAT) {
		sslogerr(ss, "nonat tunnel %s\n", addr2str(AF_INET6, src6));
		return -1;
	}

	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = proto;
	nat0.flags = ALL_DST;
	memcpy(&nat0.src, src, 4);
	memcpy(&nat0.sport, sport, 2);
	n = nat_splay_find(pr, &nat0, 1, 1);
	if (n == NULL) {
		sslogerr(ss, "not found\n");
		return -1;
	}

	del_nat(n);
	return 0;
}

/* Delete a A+P/PRR null NAT entry */

int
del_prr(struct sess *ss, u_char *src6, u_int proto, u_char *src, u_char *sport)
{
	struct nat nat0, *n;
	struct tunnel *t;
	u_char pr;

	if (proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	t = tunnel_lookup(src6);
	if (t == NULL) {
		sslogerr(ss, "no tunnel %s\n", addr2str(AF_INET6, src6));
		return -1;
	} else if (t->flags & TUNNONAT) {
		sslogerr(ss, "nonat tunnel %s\n", addr2str(AF_INET6, src6));
		return -1;
	}

	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = proto;
	nat0.flags = ALL_DST | PRR_NULL;
	memcpy(&nat0.src, src, 4);
	memcpy(&nat0.sport, sport, 2);
	n = nat_splay_find(pr, &nat0, 1, 1);
	if (n == NULL) {
		sslogerr(ss, "not found\n");
		return -1;
	} else if ((n->flags & PRR_NULL) == 0) {
		sslogerr(ss, "found regular static entry\n");
		return -1;
	}

	del_nat(n);
	return 0;
}

/* Delete a no-nat entry (from del_tunnel()) */

int
del_nonat(struct sess *ss, u_char *peer)
{
	struct tunnel *t, *x;

	t = tunnel_lookup(peer);
	if (t == NULL) {
		sslogerr(ss,
			 "already unbound[%s]\n",
			 addr2str(AF_INET6, peer));
		return -1;
	} else if ((t->flags & TUNNONAT) == 0) {
		sslogerr(ss,
			 "not a nonat tunnel[%s]\n",
			 addr2str(AF_INET6, peer));
		return -1;
	}
	ISC_STAILQ_FOREACH(x, &nonats, nchain)
		if (x == t)
			break;
	if (x == NULL) {
		logcrit("can't find nonat[%s]\n",
			addr2str(AF_INET6, peer));
		return -1;
	}
	ISC_STAILQ_REMOVE(&nonats, t, tunnel, nchain);
	free(t->nndata);
	t->nndata = NULL;
	if (t == tunnel_debugged)
		tunnel_debugged = NULL;
	t->flags &= ~(TUNDEBUG | TUNNONAT);
	ISC_DECR(tuncnt, "tuncnt");
	trace_tunnel(t, "del");
	if ((t->hash < tunhashsz) && (tunhash[t->hash] == t))
		tunhash[t->hash] = NULL;
	tunnel_tree_remove(t);
	/* t freed by tunnel_tree_remove() */
	return 0;
}

/* Reload utility */

void
gc_reload(void)
{
	struct tunnel *t, *tt;

	logdebug(10, "gc_reload");

	/* low number of no-nats: do them now */
	ISC_STAILQ_FOREACH_SAFE(t, &nonats, nchain, tt) {
		if ((t->flags & TUNNONAT) == 0)
			continue;
		if (t->ngeneration < FIRSTGEN)
			continue;
		if (t->ngeneration < lastgen) {
			logdebug(10, "GC(reload) no-nat %lx", (u_long) t);
			/* from del_nonat() */
			ISC_STAILQ_REMOVE(&nonats, t, tunnel, nchain);
			free(t->nndata);
			t->nndata = NULL;
			if (t == tunnel_debugged)
				tunnel_debugged = NULL;
			t->flags &= ~(TUNDEBUG | TUNNONAT);
			ISC_DECR(tuncnt, "tuncnt");
			trace_tunnel(t, "del");
			if ((t->hash < tunhashsz) && (tunhash[t->hash] == t))
				tunhash[t->hash] = NULL;
			tunnel_tree_remove(t);
		}
	}
	needgc = 2;
	gc_ptr = NULL;
}

void
bt_reload(void)
{
	struct tunnel *t;

	logdebug(10, "bt_reload");

	/* low number of no-nats: do them now */
	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		if ((t->flags & TUNNONAT) == 0)
			continue;
		if (t->ngeneration < FIRSTGEN)
			continue;
		if (t->ngeneration > lastgen) {
			logdebug(10, "BT(reload) no-nat %lx", (u_long) t);
			t->ngeneration = lastgen;
		}
	}
	needbt = 2;
	bt_ptr = NULL;
}

/*
 * Data structures
 *	lists
 */

/* IPv6 ACLs */

void
list_acl6(FILE *s)
{
	struct acl6 *a;
	u_int plen;
	
	if (s == NULL)
		s = stdout;
	ISC_STAILQ_FOREACH(a, &acl6s, chain) {
		for (plen = 0; plen < 129; plen++)
			if (memcmp(a->mask, mask6[plen], 16) == 0)
				break;
		if (plen > 128) {
			logcrit("illegal acl6 %s\n",
				addr2str(AF_INET6, a->addr));
			continue;
		}
		fprintf(s, "acl6 %s/%u\n",
			addr2str(AF_INET6, a->addr), plen);
	}
}

/* IPv4 ACLs */

void
list_private(FILE *s)
{
	struct acl4 *a;
	u_int plen;
	
	if (s == NULL)
		s = stdout;
	ISC_STAILQ_FOREACH(a, &acl4s, chain) {
		for (plen = 0; plen < 33; plen++)
			if (memcmp(a->mask, mask4[plen], 4) == 0)
				break;
		if (plen > 32) {
			logcrit("illegal acl4 %s\n",
				addr2str(AF_INET, a->addr));
			continue;
		}
		fprintf(s, "default private %s/%u\n",
			addr2str(AF_INET, a->addr), plen);
	}
}

/* pools */

void
list_pools(FILE *s)
{
	struct pool *ns;
	u_int i;

	if (s == NULL)
		s = stdout;
	for (i = 0; i < poolcnt; i++) {
		ns = pools[i];
		if (ns == NULL)
			continue;
		fprintf(s, "pool %s tcp %u-%u\n",
			addr2str(AF_INET, ns->addr),
			ns->minport[0], ns->maxport[0]);
		fprintf(s, "pool %s udp %u-%u\n",
			addr2str(AF_INET, ns->addr),
			ns->minport[1], ns->maxport[1]);
		fprintf(s, "pool %s echo %u-%u\n",
			addr2str(AF_INET, ns->addr),
			ns->minport[2], ns->maxport[2]);
	}
}

/* nats */

void
list_nat_elm(FILE *s, struct nat *n, int lstatic, int lprr, int ldynamic)
{
	u_int p;

	if (n->tunnel == NULL) {
		logcrit("nat without tunnel?\n");
		return;
	}
	if (n->flags & ALL_DST) {
		if (n->flags & PRR_NULL) {
			if (!lprr)
				return;
			if ((n->proto != IPTCP) && (n->proto != IPUDP)) {
				logcrit("prr with illegal protocol\n");
				return;
			}
			p = n->sport[0] << 8;
			p |= n->sport[1];
			fprintf(s, "prr %s %s %s %u\n",
				addr2str(AF_INET6, n->tunnel->remote),
				proto2str(n->proto),
				addr2str(AF_INET, n->src), p);
		} else {
			if (!lstatic)
				return;
			if ((n->proto != IPTCP) && (n->proto != IPUDP)) {
				logcrit("static nat with illegal protocol\n");
				return;
			}
			p = n->sport[0] << 8;
			p |= n->sport[1];
			fprintf(s, "nat %s %s %s %u",
				addr2str(AF_INET6, n->tunnel->remote),
				proto2str(n->proto),
				addr2str(AF_INET, n->src), p);
			p = n->nport[0] << 8;
			p |= n->nport[1];
			fprintf(s, " %s %u\n", addr2str(AF_INET, n->nsrc), p);
		}
	} else {
		if (!ldynamic)
			return;
		p = n->sport[0] << 8;
		p |= n->sport[1];
		fprintf(s, "<> %s %s %s %u",
			addr2str(AF_INET6, n->tunnel->remote),
			proto2str(n->proto),
			addr2str(AF_INET, n->src), p);
		p = n->nport[0] << 8;
		p |= n->nport[1];
		fprintf(s, " %s %u", addr2str(AF_INET, n->nsrc), p);
		p = n->dport[0] << 8;
		p |= n->dport[1];
		fprintf(s, " %s %u\n", addr2str(AF_INET, n->dst), p);
	}
}	

void
list_nat_branch(FILE *s, struct nat *n, int lstatic, int lprr, int ldynamic)
{
	if (n == NULL)
		return;
	list_nat_branch(s, n->left, lstatic, lprr, ldynamic);
	list_nat_elm(s, n, lstatic, lprr, ldynamic);
	list_nat_branch(s, n->right, lstatic, lprr, ldynamic);
}

void
list_nat(FILE *s, int lstatic, int lprr, int ldynamic)
{
	u_char i;

	for (i = 0; i < PRCNT; i++) {
		if (nat_tree[i] == NULL)
			continue;
		list_nat_branch(s, nat_tree[i]->left,
				lstatic, lprr, ldynamic);
		list_nat_elm(s, nat_tree[i],
			     lstatic, lprr, ldynamic);
		list_nat_branch(s, nat_tree[i]->right,
				lstatic, lprr, ldynamic);
	}
}

void
list_snat(FILE *s)
{
	if (s == NULL)
		s = stdout;
	list_nat(s, 1, 0, 0);
}

void
list_prr(FILE *s)
{
	if (s == NULL)
		s = stdout;
	list_nat(s, 0, 1, 0);
}

void
list_confnat(FILE *s)
{
	if (s == NULL)
		s = stdout;
	list_nat(s, 1, 1, 0);
}

void
list_dynnat(FILE *s)
{
	if (s == NULL)
		s = stdout;
	list_nat(s, 0, 0, 1);
}

void
list_allnat(FILE *s)
{
	if (s == NULL)
		s = stdout;
	list_nat(s, 1, 1, 1);
}

void
list_globalnat(FILE *s)
{
	struct nat *n;

	if (s == NULL)
		s = stdout;
	ISC_LIST_FOREACH(n, &confnats, gchain) {
		if (n->generation < lastgen)
			continue;
		list_nat_elm(s, n, 1, 1, 0);
	}
}

/* no-nat */

void
list_nonat(FILE *s)
{
	struct tunnel *t;

	if (s == NULL)
		s = stdout;
	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		if ((t->flags & TUNNONAT) == 0) {
			logcrit("a not no-nat in no-nat list for %s",
				addr2str(AF_INET6, t->remote));
			continue;
		}
		fprintf(s, "nonat %s %s/%u\n",
			addr2str(AF_INET6, t->remote),
			addr2str(AF_INET, t->nnaddr), t->nnplen);
	}
}

/* session dependent */

void
list_session(FILE *s, struct sess *ss)
{
	struct tunnel *t;
	struct nat *n;

	if (s == NULL)
		s = stdout;
	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		if ((t->flags & TUNNONAT) == 0)
			continue;
		if (t->ngeneration != ss->generation)
			continue;
		fprintf(s, "nonat %s %s/%u\n",
			addr2str(AF_INET6, t->remote),
			addr2str(AF_INET, t->nnaddr), t->nnplen);
	}
	ISC_LIST_FOREACH(n, &ss->snats, gchain)
		list_nat_elm(s, n, 1, 1, 0);
}

/* tunnels */

void
list_tunnel_elm(FILE *s, struct tunnel *t)
{
	if ((t->flags & TUNGLUE) != 0)
		return;
	fprintf(s, "tunnel %s %s\n",
		addr2str(AF_INET6, t->remote),
		addr2str(AF_INET, pools[t->srcidx]->addr));
	if (t->mtu != tundefmtu)
		fprintf(s, "mtu %u\n", (u_int) t->mtu);
}

void
list_tunnel_branch(FILE *s, struct tunnel *t)
{
	if (t == NULL)
		return;
	list_tunnel_branch(s, t->left);
	list_tunnel_elm(s, t);
	list_tunnel_branch(s, t->right);
}

void
list_tunnel_tree(FILE *s)
{
	if (s == NULL)
		s = stdout;
	if (tunnel_tree == NULL)
		return;
	list_tunnel_branch(s, tunnel_tree->left);
	list_tunnel_elm(s, tunnel_tree);
	list_tunnel_branch(s, tunnel_tree->right);
}

/*
 * Commands
 */

/* Sub-command help */

int
cmd_sub_help(struct sess *ss, char *prefix, struct cmd *cmds)
{
	struct cmd *c;

	fprintf(ss->ssout, "%s sub-commands:\n", prefix);
	for (c = cmds; c->name != NULL; c++)
		fprintf(ss->ssout, " %s %s\n", prefix, c->name);
	return 0;
}

/* Debug commands */

int
cmd_debug_check(struct sess *ss, char *tok, char *usage)
{
	if (tok == NULL) {
		logdebug(0, "check tunnels");
		check_tunnels();
		logdebug(0, "check nonats");
		check_nonats();
		logdebug(0, "check sessions");
		check_sessions();
		logdebug(0, "check pools");
		check_pools();
		logdebug(0, "check nats");
		check_nats();
		return 0;
	}
	if (strtok(NULL, " \t") != NULL)
		goto usage;

	if (strcasecmp(tok, "nat") == 0)
		check_nats();
	else if (strcasecmp(tok, "nonat") == 0)
		check_nonats();
	else if (strcasecmp(tok, "pool") == 0)
		check_pools();
	else if (strcasecmp(tok, "session") == 0)
		check_sessions();
	else if (strcasecmp(tok, "tunnel") == 0)
		check_tunnels();
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_disable(struct sess *ss, char *tok, char *usage)
{
	if (tunnel_debugged != NULL) {
		tunnel_debugged->flags &= ~TUNDEBUG;
		tunnel_debugged = NULL;
	}
	if (tok == NULL)
		return 0;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strncasecmp(tok, "clear", 5) != 0)
		goto usage;
	debugrcv6 = debugrcv4 = debugsent6 = debugsent4 = 0;
	debugnatin = debugprrin = debugnaticmpin6 = debugnaticmpin4 = 0;
	debugnatout = debugnaticmpout = 0;
	debugtcpmss = debugmsspatched = 0;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_dropped(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_dropped(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_enable(struct sess *ss, char *tok, char *usage)
{
	struct tunnel *t;
	u_char peer[16];

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	if (tunnel_debugged != NULL) {
		/* don't reset the flags for multiple tunnel debug?*/
#ifdef notyet
		tunnel_debugged->flags &= ~TUNDEBUG;
#endif
		tunnel_debugged = NULL;
	}
	t = tunnel_lookup(peer);
	if (t == NULL) {
		sslogerr(ss,
			 "can't find tunnel[%s]\n",
			 addr2str(AF_INET6, peer));
		return -1;
	}
	t->flags |= TUNDEBUG;
	tunnel_debugged = t;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_fragment(struct sess *ss, char *tok, char *usage)
{
	char *ep = NULL;
	long addr;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strncasecmp(tok, "IPv6", 4) == 0) {
		print_frags6(ss->ssout);
		return 0;
	}
	if (strncasecmp(tok, "in", 2) == 0) {
		print_fragsin(ss->ssout);
		return 0;
	}
	if (strncasecmp(tok, "out", 3) == 0) {
		print_fragsout(ss->ssout);
		return 0;
	}
	addr = strtol(tok, &ep, 16);
	if (*ep != '\0')
		goto usage;
	print_frag(ss->ssout, (struct frag *) addr);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_hash(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_hashes(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "debug", debugcmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_nat(struct sess *ss, char *tok, char *usage)
{
	char *ep = NULL;
	long addr;

	if (tok == NULL) {
		print_nat_heap(ss->ssout, 0);
		print_nat_tree(ss->ssout);
		return 0;
	}
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	addr = strtol(tok, &ep, 16);
	if (*ep != '\0')
		goto usage;
	print_nat(ss->ssout, (struct nat *) addr);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_nonat(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_nonats(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_pool(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_pools(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_session(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_sessions(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_set(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL) {
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		debuglevel = atoi(tok);
	} else
		debuglevel = 1;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_stat(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	print_stats(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_debug_tunnel(struct sess *ss, char *tok, char *usage)
{
	u_char peer[16];

	if (tok == NULL)
		print_tunnel_tree(ss->ssout);
	else {
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		if (inet_pton(AF_INET6, tok, peer) != 1)
			goto usage;
		print_tunnel(ss->ssout, peer);
	}
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

/* Default commands */

int
cmd_default_fragment(struct sess *ss, char *tok, char *usage)
{
	int v;
	u_char i;

	if (strcasecmp(tok, "equal") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		return cmd_eqfrag(ss, tok,
				  "usage: default fragment equal on|off\n");
	} else if (strcasecmp(tok, "lifetime") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		v = atoi(tok);
		if ((v <= 0) || (v > 1200)) {
			sslogerr(ss, "bad fragment lifetime %s\n", tok);
			return -1;
		}
		frag_lifetime = v;
		return 0;
	} else if (strcasecmp(tok, "ipv6") == 0)
		i = 0;
	else if (strcasecmp(tok, "in") == 0)
		i = 1;
	else if (strcasecmp(tok, "out") == 0)
		i = 2;
	else
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if ((strcasecmp(tok, "maxcount") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	v = atoi(tok);
	if ((v < 0) || (v > 16535)) {
		sslogerr(ss, "bad fragment maxcount %s\n", tok);
		return -1;
	}
	frag_maxcnt[i] = v;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "default", defaultcmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_hold(struct sess *ss, char *tok, char *usage)
{
	int l;

	if ((strcasecmp(tok, "lifetime") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	l = atoi(tok);
	if ((l < 0) || (l > 600)) {
		sslogerr(ss, "bad lifetime %s\n", tok);
		goto usage;
	}
	hold_lifetime = l;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_nat(struct sess *ss, char *tok, char *usage)
{
	int l;
	u_char i;

	if ((strcasecmp(tok, "lifetime") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if (strcasecmp(tok, "tcp") == 0)
		i = 0;
	else if (strcasecmp(tok, "closed") == 0)
		i = 1;
	else if (strcasecmp(tok, "udp") == 0)
		i = 2;
	else if (strcasecmp(tok, "icmp") == 0)
		i = 3;
	else if (strcasecmp(tok, "retrans") == 0)
		i = 4;
	else
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if ((strcasecmp(tok, "lifetime") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if ((i == 1) && (strcasecmp(tok, "tcp") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	l = atoi(tok);
	if ((l <= 0) || (l > 36000)) {
		sslogerr(ss, "bad lifetime %s\n", tok);
		goto usage;
	}
	nat_lifetime[i] = l;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_pool(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	int minport, maxport;
	u_char pr;

	if (strcasecmp(tok, "tcp") == 0)
		pr = TCPPR;
	else if (strcasecmp(tok, "udp") == 0)
		pr = UDPPR;
	else if ((strcasecmp(tok, "echo") == 0) ||
		 (strcasecmp(tok, "icmp") == 0))
		pr = ICMPPR;
	else
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if ((ntok = strtok(tok, "-")) == NULL)
		goto usage;
	minport = atoi(ntok);
	if ((ntok = strtok(NULL, "")) == NULL)
		goto usage;
	maxport = atoi(ntok);
	if ((minport < 0) || (maxport > 65535) || (minport > maxport))
		goto usage;	
	if ((minport == 0) && (pr != ICMPPR))
		goto usage;
	poolmin[pr] = minport;
	poolmax[pr] = maxport;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_private(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	int i, plen;
	u_char addr[4];
	const u_char *mask;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	tok = strtok(tok, "/");
	if (tok == NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, addr) != 1)
		goto usage;
	ntok = strtok(NULL, "");
	if (ntok == NULL)
		goto usage;
	plen = atoi(ntok);
	if ((plen < 0) || (plen > 32))
		goto usage;
	mask = mask4[plen];
	for (i = 0; i < 4; i++)
		if ((addr[i] & ~mask[i]) != 0) {
			sslogerr(ss, "bad prefix %s/%s\n", tok, ntok);
			return -1;
		}
	return add_private(ss, addr, (u_int) plen);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_default_tunnel(struct sess *ss, char *tok, char *usage)
{
	int v;
	u_char i;

	if (strcasecmp(tok, "auto") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		return cmd_autotunnel(ss, tok,
				      "usage: default tunnel auto on|off\n");
	} else if (strcasecmp(tok, "mss") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		return cmd_defmss(ss, tok,
				  "usage: default tunnel mss on|off\n");
	} else if (strcasecmp(tok, "mtu") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		return cmd_defmtu(ss, tok,
				  "usage: default tunnel mtu <mtu>\n");
	} else if (strcasecmp(tok, "toobig") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		return cmd_deftoobig(ss, tok,
				     "usage: default tunnel "
				     "toobig on|off|strict\n");
	} else if (strcasecmp(tok, "fragment") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		if (strcasecmp(tok, "ipv6") == 0)
			i = 0;
		else if (strcasecmp(tok, "ipv4") == 0)
			i = 1;
		else
			goto usage;
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		if ((strcasecmp(tok, "maxcount") == 0) &&
		    ((tok = strtok(NULL, " \t")) == NULL))
			goto usage;
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		v = atoi(tok);
		if ((v <= 0) || (v > 255)) {
			sslogerr(ss, "bad tunnel fragment maxcount %s\n", tok);
			return -1;
		}
		fragtn_maxcnt[i] = v;
		return 0;
	} else if (strcasecmp(tok, "nat") != 0)
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if (strcasecmp(tok, "tcp") == 0)
		i = TCPPR;
	else if (strcasecmp(tok, "udp") == 0)
		i = UDPPR;
	else
		i = ICMPPR;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if (strcasecmp(tok, "maxcount") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		v = atoi(tok);
		if ((v <= 0) || (v > 65535)) {
			sslogerr(ss, "bad tunnel nat maxcount %s\n", tok);
			return -1;
		}
		maxtnatcnt[i] = v;
		return 0;
	} else if (strcasecmp(tok, "rate") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		v = atoi(tok);
		if ((v <= 0) || (v > 255)) {
			sslogerr(ss, "bad tunnel nat rate %s\n", tok);
			return -1;
		}
		maxtnatrt[i] = v;
		return 0;
	}
    usage:
	sslogerr(ss, usage);
	return -1;
}

void
conf_global_close(void)
{
	u_char pr;

	for (pr = 0; pr < PRCNT; pr++)
		if (poolmin[pr] > poolmax[pr]) {
			u_int v = poolmin[pr];

			poolmin[pr] = poolmax[pr];
			poolmax[pr] = v;
		}
}

/* Delete commands */

int
cmd_delete_acl6(struct sess *ss, char *tok, char *usage)
{
	u_char addr[16];
	int ret;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, addr) != 1)
		goto usage;
	ret = del_acl6(ss, addr);
	if (ISC_STAILQ_EMPTY(&acl6s)) {
		sslogerr(ss, "No more IPv6 ACL?!\n");
		return -1;
	}
	return ret;

    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "delete", deletecmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_nat(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_int proto, sp;
	u_char peer[16], src[4], sport[2];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	proto = (strcasecmp(tok, "tcp") == 0) ? IPTCP : IPUDP;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	sp = atoi(ntok);
	sport[0] = sp >> 8;
	sport[1] = sp & 0xff;
	return del_snat(ss, peer, proto, src, sport);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_nonat(struct sess *ss, char *tok, char *usage)
{
	u_char peer[16];

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	return del_nonat(ss, peer);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_private(struct sess *ss, char *tok, char *usage)
{
	u_char addr[4];
	int ret;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, addr) != 1)
		goto usage;
	ret = del_private(ss, addr);
	if (ISC_STAILQ_EMPTY(&acl4s)) {
		sslogerr(ss, "No more IPv4 ACL?!\n");
		return -1;
	}
	return ret;

    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_prr(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_int proto, sp;
	u_char peer[16], src[4], sport[2];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	proto = (strcasecmp(tok, "tcp") == 0) ? IPTCP : IPUDP;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	sp = atoi(ntok);
	sport[0] = sp >> 8;
	sport[1] = sp & 0xff;
	return del_prr(ss, peer, proto, src, sport);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_delete_tunnel(struct sess *ss, char *tok, char *usage)
{
	u_char peer[16];

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	return del_tunnel(ss, peer);
    usage:
	sslogerr(ss, usage);
	return -1;
}

/* List commands */

int
cmd_list_acl6(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	list_acl6(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_default(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	fprintf(ss->ssout,
		"bucket tcp size %hhu\n", bucksize[TCPPR]);
	fprintf(ss->ssout,
		"bucket udp size %hhu\n", bucksize[UDPPR]);
	fprintf(ss->ssout,
		"bucket icmp size %hhu\n", bucksize[ICMPPR]);
	fprintf(ss->ssout,
		"decay 1 %.20f\n", decays[0]);
	fprintf(ss->ssout,
		"decay 5 %.20f\n", decays[1]);
	fprintf(ss->ssout,
		"decay 15 %.20f\n", decays[2]);
	fprintf(ss->ssout,
		"default fragment equal %s\n", eqfrag != 0 ? "on" : "off");
	fprintf(ss->ssout,
		"default fragment lifetime %u\n", frag_lifetime);
	fprintf(ss->ssout,
		"default fragment ipv6 maxcount %u\n", frag_maxcnt[0]);
	fprintf(ss->ssout,
		"default fragment in maxcount %u\n", frag_maxcnt[1]);
	fprintf(ss->ssout,
		"default fragment out maxcount %u\n", frag_maxcnt[2]);
	fprintf(ss->ssout,
		"default hold lifetime %u\n", hold_lifetime);
	fprintf(ss->ssout,
		"default nat tcp lifetime %d\n", nat_lifetime[0]);
	fprintf(ss->ssout,
		"default nat closed lifetime %d\n", nat_lifetime[1]);
	fprintf(ss->ssout,
		"default nat udp lifetime %d\n", nat_lifetime[2]);
	fprintf(ss->ssout,
		"default nat icmp lifetime %d\n", nat_lifetime[3]);
	fprintf(ss->ssout,
		"default nat retrans lifetime %d\n", nat_lifetime[4]);
	fprintf(ss->ssout,
		"default pool tcp %u-%u\n", poolmin[0], poolmax[0]);
	fprintf(ss->ssout,
		"default pool udp %u-%u\n", poolmin[1], poolmax[1]);
	fprintf(ss->ssout,
		"default pool echo %u-%u\n", poolmin[2], poolmax[2]);
	list_private(ss->ssout);
	fprintf(ss->ssout,
		"default tunnel auto %s\n",
		use_autotunnel != 0 ? "on" : "off");
	fprintf(ss->ssout,
		"default tunnel mss %s\n",
		enable_msspatch != 0 ? "on" : "off");
	fprintf(ss->ssout,
		"default tunnel mtu %u\n", (u_int) tundefmtu);
	fprintf(ss->ssout,
		"default tunnel toobig %s\n",
		default_toobig == 0 ? "off" :
		    ((default_toobig & TUNTBDROP) ? "strict" : "on"));
	fprintf(ss->ssout,
		"default tunnel fragment ipv6 maxcount %u\n",
		(u_int) fragtn_maxcnt[0]);
	fprintf(ss->ssout,
		"default tunnel fragment ipv4 maxcount %u\n",
		(u_int) fragtn_maxcnt[1]);
	fprintf(ss->ssout,
		"default tunnel nat tcp maxcount %u\n",
		(u_int) maxtnatcnt[0]);
	fprintf(ss->ssout,
		"default tunnel nat udp maxcount %u\n",
		(u_int) maxtnatcnt[1]);
	fprintf(ss->ssout,
		"default tunnel nat icmp maxcount %u\n",
		(u_int) maxtnatcnt[2]);
	fprintf(ss->ssout,
		"default tunnel nat tcp rate %u\n",
		(u_int) maxtnatrt[0]);
	fprintf(ss->ssout,
		"default tunnel nat udp rate %u\n",
		(u_int) maxtnatrt[1]);
	fprintf(ss->ssout,
		"default tunnel nat icmp rate %u\n",
		(u_int) maxtnatrt[2]);
	fprintf(ss->ssout,
		"quantum %u\n", (u_int) quantum);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "list", listcmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_nat(struct sess *ss, char *tok, char *usage)
{
	if (tok == NULL) {
		list_confnat(ss->ssout);
		return 0;
	}
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strncasecmp(tok, "conf", 3) == 0)
		list_confnat(ss->ssout);
	else if (strncasecmp(tok, "all", 3) == 0)
		list_allnat(ss->ssout);
	else if (strncasecmp(tok, "dyn", 3) == 0)
		list_dynnat(ss->ssout);
	else if ((strncasecmp(tok, "prr", 3) == 0) ||
		 (strncasecmp(tok, "a+p", 3) == 0))
		list_prr(ss->ssout);
	else if (strncasecmp(tok, "static", 6) == 0)
		list_snat(ss->ssout);
	else if (strncasecmp(tok, "global", 6) == 0)
		list_globalnat(ss->ssout);
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_nonat(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	list_nonat(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_pool(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	list_pools(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_list_session(struct sess *ss0, char *tok, char *usage)
{
	struct sess *ss;
	u_int gen;

	if (tok == NULL) {
		list_session(ss0->ssout, ss0);
		return 0;
	}
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	gen = atoi(tok);
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		if ((ss->name != NULL) && (strcmp(ss->name, tok) == 0))
			break;
		if ((gen != 0) && (ss->generation == gen))
			break;
	}
	if (ss == NULL) {
		sslogerr(ss0, "can't find session %s\n", tok);
		return -1;
	}
	list_session(ss0->ssout, ss);
	return 0;
    usage:
	sslogerr(ss0, usage);
	return -1;
}

int
cmd_list_tunnel(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	list_tunnel_tree(ss->ssout);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

/* Session commands */

int
cmd_session_close(struct sess *ss0, char *tok, char *usage)
{
	struct sess *ss;
	u_int gen;

	if (tok == NULL) {
		if (ss0->locked) {
			sslogerr(ss0, "session locked against close\n");
			return -1;
		}
		return ss0->sstype->ccclose(ss0);
	}
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	gen = atoi(tok);
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		if ((ss->name != NULL) && (strcmp(ss->name, tok) == 0))
			break;
		if ((gen != 0) && (ss->generation == gen))
			break;
	}
	if (ss == NULL) {
		sslogerr(ss0, "can't find session %s\n", tok);
		return -1;
	} else if (ss->locked) {
		sslogerr(ss0, "session locked against close\n");
		return -1;
	}
	return ss->sstype->ccclose(ss);
    usage:
	sslogerr(ss0, usage);
	return -1;
}

int
cmd_session_config(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "on") == 0)
		ss->section = 12;
	else if (strcasecmp(tok, "off") == 0)
		ss->section = 8;
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_session_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "session", sessioncmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_session_log(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (ss->locked & 2) {
		sslogerr(ss, "session locked against this operation\n");
		return -1;
	}
	if (strcasecmp(tok, "on") == 0) {
		if (ss->sserr == NULL) {
			ss->sserr = fdopen(dup(ss->fd), "w");
			if (ss->sserr == NULL) {
				sslogerr(ss, "fdopen(err)\n");
				return -1;
			}
			setlinebuf(ss->sserr);
		}
		return 0;
	} else if (strcasecmp(tok, "off") == 0) {
		if (ss->sserr != NULL) {
			(void) fclose(ss->sserr);
			ss->sserr = NULL;
		}
		return 0;
	}
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_session_name(struct sess *ss, char *tok, char *usage)
{
	if (tok == NULL) {
		if (ss->name == NULL)
			fprintf(ss->ssout,
				"no name, generation=%u\n",
				ss->generation);
		else
			fprintf(ss->ssout, "name=\"%s\", generation=%u\n",
				ss->name, ss->generation);
		return 0;
	} else if (strtok(NULL, " \t") != NULL)
		goto usage;
	else if (ss->locked & 2) {
		sslogerr(ss, "session locked against this operation\n");
		return -1;
	}
	if (ss->name != NULL)
		free(ss->name);
	ss->name = strdup(tok);
	if (ss->name == NULL) {
		sslogerr(ss, "strdup(name): %s\n", strerror(errno));
		return -1;
	}
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_session_notify(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (ss->locked & 2) {
		sslogerr(ss, "session locked against this operation\n");
		return -1;
	}
	if (strcasecmp(tok, "on") == 0) {
		if (ss->ssnot == NULL) {
			ss->ssnot = fdopen(dup(ss->fd), "w");
			if (ss->ssnot == NULL) {
				sslogerr(ss, "fdopen(not)\n");
				return -1;
			}
			setlinebuf(ss->ssnot);
		}
		return 0;
	} else if (strcasecmp(tok, "off") == 0) {
		if (ss->ssnot != NULL) {
			(void) fclose(ss->ssnot);
			ss->ssnot = NULL;
		}
		return 0;
	}
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_show_help(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	return cmd_sub_help(ss, "show", showcmd);
    usage:
	sslogerr(ss, usage);
	return -1;
}

/* Generic command dispatcher */

int
cmd_dispatch(struct sess *ss, char *tok, struct cmd *cmd, char *root)
{
	int c;
	char usage[256];

	c = tolower(*tok);

	for ( ; cmd->name != NULL && cmd->name[0] < c; cmd++)
		/* match first letter of command */;

	for ( ; cmd->name != NULL && cmd->name[0] == c; cmd++) {
		if (strncasecmp(tok, cmd->name, cmd->len) == 0) {
			if (root == NULL)
				sprintf(usage, "usage: %s %s\n",
					cmd->name, cmd->usage);
			else
				sprintf(usage, "usage: %s %s %s\n",
					root, cmd->name, cmd->usage);
			tok = strtok(NULL, " \t");
			if ((tok == NULL) && cmd->required_args) {
				sslogerr(ss, usage);
				return -1;
			}
			if ((cmd->section & ss->section) == 0) {
				if (cmd->section < ss->section) {
					if (reloading)
						return 0;
					goto wrong_section;
				}
				if (cmd->section & 2) {
					conf_global_close();
					ss->section = 2;
				} else if (cmd->section & 4)
					ss->section = 4;
				else
					goto wrong_section;
			}
			return cmd->func(ss, tok, usage);
		}
	}

	if (root == NULL)
		sslogerr(ss, "unknown command: %s\n", tok);
	else
		sslogerr(ss, "unknown command: %s %s\n", root, tok);
	return -1;

    wrong_section:
	if (root == NULL)
		sslogerr(ss, "\"%s\" in wrong section\n", cmd->name);
	else
		sslogerr(ss, "\"%s %s\" in wrong section\n", root, cmd->name);
	return -1;
}

/* decode one line of config/command */

int
cmdline(struct sess *ss, char *line)
{
	char *l, *tok;

	if ((ss == NULL) || (ss->fd == -1)) {
		logcrit("dangling session\n");
		return -1;
	}
	l = line;
	while ((line[strlen(l) - 1] == '\n') || (line[strlen(l) - 1] == '\r'))
		line[strlen(l) - 1] = '\0';

	tok = strtok(l, " \t");
	if (tok == NULL)
		return 0;
	switch (*tok) {
	case '#':
	case '\0':
		return 0;

	case '?':
		return cmd_help(ss, NULL, "");

	default:
		return cmd_dispatch(ss, tok, cmd, NULL);
	}
}

/* Top-level commands */

int
cmd_debug(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, debugcmd, "debug");
}

int
cmd_default(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, defaultcmd, "default");
}

int
cmd_delete(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, deletecmd, "delete");
}

int
cmd_list(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, listcmd, "list");
}

int
cmd_session(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, sessioncmd, "session");
}

int
cmd_show(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	return cmd_dispatch(ss, tok, showcmd, "show");
}

int
cmd_abort(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	logcrit("abort (pid=%u)\n", (u_int) getpid());
	abort();
	logcrit("unreachable\n");
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_acl6(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	int i, plen;
	u_char addr[16];
	const u_char *mask;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	tok = strtok(tok, "/");
	if (tok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, addr) != 1)
		goto usage;
	ntok = strtok(NULL, "");
	if (ntok == NULL)
		goto usage;
	plen = atoi(ntok);
	if ((plen < 0) || (plen > 128))
		goto usage;
	mask = mask6[plen];
	for (i = 0; i < 16; i++)
		if ((addr[i] & ~mask[i]) != 0) {
			sslogerr(ss, "bad prefix %s/%s\n", tok, ntok);
			return -1;
		}
	return add_acl6(ss, addr, (u_int) plen);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_address(struct sess *ss, char *tok, char *usage)
{
	char *ntok;

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "endpoint") == 0) {
		if (local6_set) {
			sslogerr(ss,
				 "endpoint address is already set to %s\n",
				 addr2str(AF_INET6, local6));
			return -1;
		}
		if (inet_pton(AF_INET6, ntok, local6) != 1)
			goto usage;
		local6_set = 1;
		return 0;
	} else if (strcasecmp(tok, "icmp") == 0) {
		if (icmpsrc_set) {
			sslogerr(ss,
				 "icmp address is already set to %s\n",
				 addr2str(AF_INET, icmpsrc));
			return -1;
		}
		if (inet_pton(AF_INET, ntok, icmpsrc) != 1)
			goto usage;
		icmpsrc_set = 1;
		return 0;
	}
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_autotunnel(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "on") == 0)
		use_autotunnel = 1;
	else if (strcasecmp(tok, "off") == 0)
		use_autotunnel = 0;
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_bucket(struct sess *ss, char *tok, char *usage)
{
	int sz;
	u_char pr;

	if (strcasecmp(tok, "tcp") == 0)
		pr = TCPPR;
	else if (strcasecmp(tok, "udp") == 0)
		pr = UDPPR;
	else
		pr = ICMPPR;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if ((strcasecmp(tok, "size") == 0) &&
	    ((tok = strtok(NULL, " \t")) == NULL))
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	sz = atoi(tok);
	if ((sz <= 0) || (sz > 255)) {
		sslogerr(ss, "bad size %s\n", tok);
		goto usage;
	}
	bucksize[pr] = sz;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_decay(struct sess *ss, char *tok, char *usage)
{
	char *ep = NULL;
	u_char i;

	if (strcasecmp(tok, "1") == 0)
		i = 0;
	else if (strcasecmp(tok, "5") == 0)
		i = 1;
	else if (strcasecmp(tok, "15") == 0)
		i = 2;
	else
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	decays[i] = strtod(tok, &ep);
	if (*ep != '\0')
		goto usage;
	if ((decays[i] < 0.0) || (decays[i] > 1.0)) {
		sslogerr(ss, "bad decay %f\n", decays[i]);
		return -1;
	}
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_defmss(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "on") == 0)
		enable_msspatch = 1;
	else if (strcasecmp(tok, "off") == 0)
		enable_msspatch = 0;
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_defmtu(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	tundefmtu = atoi(tok);
	if (tundefmtu < TUNMINMTU) {
		sslogerr(ss,
			 "%hu illegal value for defmtu, reset to %d\n",
			 tundefmtu,
			 TUNMINMTU);
		tundefmtu = TUNMINMTU;
	}
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_deftoobig(struct sess *ss, char *tok, char *usage)
{
	if (strcasecmp(tok, "on") == 0) {
		default_toobig = TUNTBICMP;
	} else if (strcasecmp(tok, "off") == 0) {
		default_toobig = 0;
	} else if (strcasecmp(tok, "strict") == 0) {
		default_toobig = TUNTBDROP | TUNTBICMP;
	} else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_echo(struct sess *ss, char *tok, char *usage)
{
	usage = usage;
	fprintf(ss->ssout, "echo %s\n", tok);
	return 0;
}

int
cmd_eqfrag(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "on") == 0)
		eqfrag = 1;
	else if (strcasecmp(tok, "off") == 0)
		eqfrag = 0;
	else
		goto usage;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_fork(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	if (ss->locked & 2) {
		sslogerr(ss, "session locked against this operation\n");
		return -1;
	}
	if (loading) {
		sslogerr(ss, "operation impossible while loading a file\n");
		return -1;
	}
	logdebug(0, "forking(parent pid=%u)", (u_int) getpid());
	if (fork() == 0)
		fork_child(ss);
	(void) ss->sstype->ccclose(ss);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_help(struct sess *ss, char *tok, char *usage)
{
	struct cmd *c;

	if (tok == NULL) {
		fprintf(ss->ssout, "available commands:\n");
		for (c = cmd; c->name != NULL; c++)
			if ((c->section & ss->section) != 0)
				fprintf(ss->ssout, " %s\n", c->name);
		return 0;
	} else if (strtok(NULL, " \t") != NULL)
		goto usage;
	fprintf(ss->ssout, "all commands:\n");
	for (c = cmd; c->name != NULL; c++)
		fprintf(ss->ssout, " %s\n", c->name);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_kill(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	logdebug(0, "quitting");
	return 1;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_load(struct sess *ss, char *tok, char *usage)
{
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	return load_file(ss, tok);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_mss(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_char peer[16];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	if (strcasecmp(ntok, "on") == 0)
		return set_tunnel_flag(ss, peer, TUNMSSFLG, TUNMSSFLG);
	else if (strcasecmp(ntok, "off") == 0)
		return set_tunnel_flag(ss, peer, 0, TUNMSSFLG);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_mtu(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_int mtu;
	u_char peer[16];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	mtu = atoi(ntok);
	return set_tunnel_mtu(ss, peer, mtu, 1);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_nat(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_int proto, sp, np;
	u_char peer[16], src[4], nsrc[4], sport[2], nport[2];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	proto = (strcasecmp(tok, "tcp") == 0) ? IPTCP : IPUDP;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	sp = atoi(tok);
	sport[0] = sp >> 8;
	sport[1] = sp & 0xff;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, nsrc) != 1)
		goto usage;
	np = atoi(ntok);
	nport[0] = np >> 8;
	nport[1] = np & 0xff;
	if (reloading)
		return reload_snat(ss, peer, proto, src, sport, nsrc, nport);
	return add_snat(ss, peer, proto, src, sport, nsrc, nport);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_nonat(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	int plen;
	u_char peer[16], addr[4];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = strtok(ntok, "/");
	if (tok == NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, addr) != 1)
		goto usage;
	ntok = strtok(NULL, "");
	if (ntok == NULL)
		goto usage;
	plen = atoi(ntok);
	if ((plen < 0) || (plen > 32))
		goto usage;
	if (reloading)
		return reload_nonat(ss, peer, addr, (u_int) plen);
	return add_nonat(ss, peer, addr, (u_int) plen);
    usage:
	sslogerr(ss, usage);
	return -1;
}	

int
cmd_noop(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	logdebug(0, "alive");
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_pool(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_char src[4];
	u_int proto;
	int minport, maxport;

	ntok = strtok(NULL, " \t");
	if (ntok == NULL) {
		if (inet_pton(AF_INET, tok, src) != 1)
			goto usage;
		return add_pool(ss, src);
	}
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (strcasecmp(tok, "tcp") == 0)
		proto = IPTCP;
	else if (strcasecmp(tok, "udp") == 0)
		proto = IPUDP;
	else if ((strcasecmp(tok, "echo") == 0) ||
		 (strcasecmp(tok, "icmp") == 0))
		proto = IPICMP;
	else
		goto usage;
	tok = strtok(ntok, "-");
	if (tok == NULL)
		goto usage;
	minport = atoi(tok);
	ntok = strtok(NULL, "");
	if (ntok == NULL)
		goto usage;
	maxport = atoi(ntok);
	if ((minport < 0) || (maxport > 65535) || (minport > maxport))
		goto usage;
	if ((minport == 0) && (proto != IPICMP))
		goto usage;
	return limit_port(ss, src, proto, (u_int) minport, (u_int) maxport);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_prr(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_int proto, sp;
	u_char peer[16], src[4], sport[2];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	proto = (strcasecmp(tok, "tcp") == 0) ? IPTCP : IPUDP;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	sp = atoi(ntok);
	sport[0] = sp >> 8;
	sport[1] = sp & 0xff;
	if (reloading)
		return reload_prr(ss, peer, proto, src, sport);
	return add_prr(ss, peer, proto, src, sport);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_quantum(struct sess *ss, char *tok, char *usage)
{
	int q;

	if (strtok(NULL, " \t") != NULL)
		goto usage;
	q = atoi(tok);
	if ((q <= 1) || (q > 255)) {
		sslogerr(ss, "bad quantum %s\n", tok);
		goto usage;
	}
	quantum = q;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_quit(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	sslogerr(ss, "use either 'session close' or 'kill'\n");
	return -1;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_reboot(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	logdebug(0, "rebooting");
	return 2;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_reload(struct sess *ss, char *tok, char *usage)
{
	if (tok != NULL)
		goto usage;
	if (reloading) {
		sslogerr(ss, "recursive reload?: in progress\n");
		return -1;
	} else if (needgc) {
		sslogerr(ss, "garbage collection in progress\n");
		return -1;
	} else if (needbt) {
		sslogerr(ss, "reload backtrack in progress\n");
		return -1;
	}
	return reload_conf(ss);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_toobig(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_char flags;
	u_char peer[16];

	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	if (strcasecmp(ntok, "on") == 0)
		flags = TUNTBICMP;
	else if (strcasecmp(ntok, "off") == 0)
		flags = 0;
	else if (strcasecmp(ntok, "strict") == 0)
		flags = TUNTBDROP | TUNTBICMP;
	else
		goto usage;
	return set_tunnel_flag(ss, peer, flags, TUNTBDROP | TUNTBICMP);
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_try(struct sess *ss, char *tok, char *usage)
{
	struct nat *n;
	char *ntok;
	u_int proto, sp, np;
	u_char peer[16], src[4], nsrc[4], sport[2], nport[2];

	if (strcasecmp(tok, "tunnel") == 0) {
		if ((tok = strtok(NULL, " \t")) == NULL)
			goto usage;
		ntok = strtok(NULL, " \t");
		if (inet_pton(AF_INET6, tok, peer) != 1)
			goto usage;
		if (ntok == NULL)
			return try_tunnel(ss, peer, NULL);
		if (inet_pton(AF_INET, ntok, src) != 1)
			goto usage;
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		return try_tunnel(ss, peer, src);
	} else if (strcasecmp(tok, "nat") != 0)
		goto usage;
	if ((tok = strtok(NULL, " \t")) == NULL)
		goto usage;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	proto = (strcasecmp(tok, "tcp") == 0) ? IPTCP : IPUDP;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, src) != 1)
		goto usage;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	sp = atoi(tok);
	sport[0] = sp >> 8;
	sport[1] = sp & 0xff;
	tok = ntok;
	ntok = strtok(NULL, " \t");
	if (ntok == NULL)
		goto usage;
	if (strtok(NULL, " \t") != NULL)
		goto usage;
	if (inet_pton(AF_INET, tok, nsrc) != 1)
		goto usage;
	np = atoi(ntok);
	nport[0] = np >> 8;
	nport[1] = np & 0xff;
	n = try_snat(ss, peer, proto, src, sport, nsrc, nport);
	if (n == NULL)
		return -1;
	fprintf(ss->ssout, "nat %s %s %s %u %s %u\n",
		addr2str(AF_INET6, peer), proto2str(proto),
		addr2str(AF_INET, src), sp,
		addr2str(AF_INET, nsrc), np);
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

int
cmd_tunnel(struct sess *ss, char *tok, char *usage)
{
	char *ntok;
	u_char peer[16], src[4];

	ntok = strtok(NULL, " \t");
	if (inet_pton(AF_INET6, tok, peer) != 1)
		goto usage;
	if (ntok != NULL) {
		if (strtok(NULL, " \t") != NULL)
			goto usage;
		if (inet_pton(AF_INET, ntok, src) != 1)
			goto usage;
		if (reloading)
			return reload_tunnel(ss, peer, src);
		if (add_stdtunnel(ss, peer, src) == NULL)
			return -1;
	} else if (reloading)
		return reload_tunnel(ss, peer, NULL);
	else if (add_stdtunnel(ss, peer, NULL) == NULL)
		return -1;
	return 0;
    usage:
	sslogerr(ss, usage);
	return -1;
}

/* load file */

int
load_file(struct sess *ss, char *filename)
{
	FILE *f;
	char line[256];
	int ln, saved, ret = 0;

	f = fopen(filename, "r");
	if (f == NULL) {
		sslogerr(ss, "fopen(load=\"%s\"): %s\n",
			 filename, strerror(errno));
		return -1;
	}
	saved = loading;
	loading = 1;
	memset(line, 0, sizeof(line));
	for (ln = 1;; ln++) {
		if (fgets(line, sizeof(line), f) == NULL)
			break;
		if (cmdline(ss, line) < 0) {
			sslogerr(ss, "command failed (\"%s\" line %d)\n",
				 filename, ln);
			ret = -1;
			break;
		}
	}
	(void) fclose(f);
	loading = saved;
	return ret;
}

/* reload config */

void
reload_finish(int backtrack)
{
	reloading = 0;
	curgen = 0;
	if (reload_stream != NULL)
		(void) fclose(reload_stream);
	reload_stream = NULL;
	reload_session->section = reload_savedsec;
	reload_session->locked = reload_savedloc;

	if (backtrack) {
		lastgen = reload_savedgen;
		sslogerr(reload_session,
			 "reload failed (line %d)\n",
			 reload_ln);
		reload_session = NULL;
		bt_reload();
	} else {
		sslogdebug0(reload_session, "reload succeeded");
		reload_session = NULL;
		gc_reload();
	}
}

int
reload_conf(struct sess *ss)
{
	char line[256];
	int remains, ret = 0;

	reload_ln = 1;
	reload_stream = fopen(aftrconfig, "r");
	if (reload_stream == NULL) {
		sslogerr(ss, "fopen(config=\"%s\"): %s\n",
			 aftrconfig, strerror(errno));
		return -1;
	}
	reload_savedgen = lastgen;
	lastgen++;
	if (lastgen == 0) {
		logcrit("generations wrap?\n");
		exit(1);
	}
	curgen = lastgen;
	reload_session = ss;
	reload_savedsec = ss->section;
	reload_savedloc = ss->locked;
	ss->section = 4;
	ss->locked = 1;
	reloading = 1;

	memset(line, 0, sizeof(line));
	for (remains = (int) quantum; remains > 0; remains--, reload_ln++) {
		if (fgets(line, sizeof(line), reload_stream) == NULL) {
			ret = 1;
			break;
		}
		if (cmdline(ss, line) < 0) {
			ret = -1;
			break;
		}
	}
	if (ret == 1) {
		reload_finish(0);
		return 0;
	} else if (ret == -1)
		reload_finish(1);
	return ret;
}

void
reload_incr(void)
{
	char line[256];
	int remains, ret = 0;
	u_int savedgen = curgen;

	curgen = lastgen;
	memset(line, 0, sizeof(line));
	for (remains = (int) quantum / 2;
	     remains > 0;
	     remains--, reload_ln++) {
		if (fgets(line, sizeof(line), reload_stream) == NULL) {
			ret = 1;
			break;
		}
		if (cmdline(reload_session, line) < 0) {
			ret = -1;
			break;
		}
	}
	curgen = savedgen;
	if (ret == 1)
		reload_finish(0);
	else if (ret == -1)
		reload_finish(1);
}

/* load config */

int
load_conf(struct sess *ss)
{
	FILE *f;
	char line[256];
	int ln;

	f = fopen(aftrconfig, "r");
	if (f == NULL) {
		logcrit("fopen(config=\"%s\"): %s\n",
			aftrconfig, strerror(errno));
		return -1;
	}
	memset(line, 0, sizeof(line));
	for (ln = 1;; ln++) {
		if (fgets(line, sizeof(line), f) == NULL) {
			(void) fclose(f);
			return 0;
		}
		if (cmdline(ss, line) < 0) {
			if (!checkconf) {
				sslogerr(ss, "config failed (line %d)\n", ln);
				(void) fclose(f);
				return -1;
			} else
				sslogerr(ss, "config error (line %d)\n", ln);
		}
	}
	logcrit("unreachable\n");
	(void) fclose(f);
	return -1;
}

/* read commands */

int
commands(struct sess *ss)
{
	char *l, line[256];
	int cc = 0, first = 0;
	u_int savedgen = curgen;
	size_t len;

	curgen = ss->generation;
	memset(line, 0, sizeof(line));
	if (ss->cpos == 0)
		first = 1;
	for (;;) {
		if (ss->fd == -1) {
			cc = 0;
			break;
		}
		if (ss->cpos == 0)
			memset(ss->cbuf, 0, sizeof(ss->cbuf));
		if (ss->cpos > 0) {
			l = strchr(ss->cbuf, '\n');
			if (l != NULL) {
				*l = '\0';
				len = strlen(ss->cbuf) + 1;
				if (len >= sizeof(line)) {
					memmove(ss->cbuf,
						ss->cbuf + len,
						sizeof(ss->cbuf) - len);
					ss->cpos -= len;
					continue;
				}
				memcpy(line, ss->cbuf, len);
				memmove(ss->cbuf,
					ss->cbuf + len,
					sizeof(ss->cbuf) - len);
				ss->cpos -= len;
				cc = cmdline(ss, line);
				if (cc > 0)
					break;
				if (cc < 0)
					sslogerr(ss, "command failed\n");
				if (reloading)
					break;
				continue;
			}
		}
		if (ss->fd == -1) {
			cc = 0;
			break;
		}
		if (ioctl(ss->fd, FIONREAD, &cc) < 0) {
			logcrit("in FIONREAD: %s\n", strerror(errno));
			exit(-1);
		}
		if (cc == 0) {
			if (first) {
				if (ss->locked) {
					logcrit("closed(ioctl)?\n");
					exit(-1);
				} else {
					sslogerr(ss,
						 "closed session(ioctl)?\n");
					(void) ss->sstype->ccclose(ss);
				}
			}
			break;
		}
		cc = read(ss->fd,
			  ss->cbuf + ss->cpos,
			  sizeof(ss->cbuf) - ss->cpos - 1);
		if (cc < 0) {
			logcrit("in read: %s\n", strerror(errno));
			exit(-1);
		}
		if (cc == 0) {
			if (ss->locked) {
				logcrit("closed(read)?\n");
				exit(-1);
			} else {
				sslogerr(ss, "closed session(read)?\n");
				(void) ss->sstype->ccclose(ss);
			}
			break;
		}
		first = 0;
		ss->cpos += cc;
	}
	curgen = savedgen;
	return cc;
}

/*
 * Control channel
 */

u_int
session_nextgen(void)
{
	struct sess *ss;
	u_int attempts;

	for (attempts = 0; attempts < 20; attempts++) {
		sesgen += 1;
		if (sesgen == FIRSTGEN) {
			sesgen = 0;
			continue;
		}
		ISC_LIST_FOREACH(ss, &sslist, chain)
			if (ss->generation == sesgen)
				goto found;
		ISC_LIST_FOREACH(ss, &orphans, chain)
			if (ss->generation == sesgen)
				goto found;
		return sesgen;
	    found:
		continue;
	}
	logcrit("unreachable\n");
	return 1;
}

void
gc_session(struct sess *ss)
{
	struct tunnel *t, *tt;
	struct nat *n;

	logdebug(10, "gc_session");

	ISC_STAILQ_FOREACH_SAFE(t, &nonats, nchain, tt) {
		if ((t->flags & TUNNONAT) == 0)
			continue;
		if (t->ngeneration == ss->generation) {
			logdebug(10, "GC(session) no-nat %lx", (u_long) t);
			/* from del_nonat() */
			ISC_STAILQ_REMOVE(&nonats, t, tunnel, nchain);
			free(t->nndata);
			t->nndata = NULL;
			if (t == tunnel_debugged)
				tunnel_debugged = NULL;
			t->flags &= ~(TUNDEBUG | TUNNONAT);
			ISC_DECR(tuncnt, "tuncnt");
			trace_tunnel(t, "del");
			if ((t->hash < tunhashsz) && (tunhash[t->hash] == t))
				tunhash[t->hash] = NULL;
			tunnel_tree_remove(t);
		}
	}

	ISC_LIST_FOREACH(n, &ss->snats, gchain) {
		if (n->generation != ss->generation)
			continue;
		n->generation = FIRSTGEN;
	}
	ISC_LIST_INSERT_HEAD(&orphans, ss, chain);
	if (!needgc) {
		needgc = 1;
		gc_ptr = NULL;
	}
}

struct sess *
stdio_open(void)
{
	static struct sess stdio_sess;
	static char *stdio_name = "tty";
	static int initialized = 0;

	if (!initialized) {
		memset(&stdio_sess, 0, sizeof(stdio_sess));
		ISC_MAGIC_SET(&stdio_sess, ISC_SESSION_MAGIC);
		ISC_LIST_INSERT_HEAD(&sslist, &stdio_sess, chain);
		stdio_sess.sstype = &ccstdio;
		stdio_sess.name = stdio_name;
		stdio_sess.generation = 1;
		sesgen = 1;
		stdio_sess.fd = fileno(stdin);
		stdio_sess.ssout = stdout;
		stdio_sess.ssnot = NULL;
		stdio_sess.sserr = stderr;
		stdio_sess.locked = 0xff;
		initialized = 1;
	}
	if (stdio_sess.fd != -1)
		return &stdio_sess;
	else
		return NULL;
}

int
stdio_close(struct sess *ss)
{
	ISC_LIST_REMOVE(ss, chain);
	if (ss->sstype != &ccstdio) {
		logcrit("bad ccclose\n");
		return -1;
	}
	/* don't close the file descriptor */
	ss->fd = -1;
	gc_session(ss);
	return 0;
}

struct sess *
unix_open(void)
{
	struct sess *ss;
	int fd;

	fd = accept(unix_fd, NULL, NULL);
	if (fd < 0) {
		logerr("accept(unix): %s\n", strerror(errno));
		return NULL;
	}
	ss = (struct sess *) malloc(sizeof(*ss));
	if (ss == NULL) {
		logerr("malloc(unix_open): %s\n", strerror(errno));
		return NULL;
	}
	memset(ss, 0, sizeof(*ss));
	ISC_MAGIC_SET(ss, ISC_SESSION_MAGIC);
	ISC_LIST_INSERT_HEAD(&sslist, ss, chain);
	ss->sstype = &ccunix;
	ss->generation = session_nextgen();
	ss->fd = fd;
	ss->section = 8;
	ss->ssout = fdopen(fd, "w");
	if (ss->ssout == NULL) {
		logerr("fdopen(out)\n");
		unix_close(ss);
		return NULL;
	}
	setlinebuf(ss->ssout);
	ss->sserr = fdopen(dup(fd), "w");
	if (ss->sserr == NULL) {
		logerr("fdopen(err)\n");
		unix_close(ss);
		return NULL;
	}
	setlinebuf(ss->sserr);
	return ss;
}

int
unix_close(struct sess *ss)
{
	ISC_LIST_REMOVE(ss, chain);
	if (ss->sstype != &ccunix) {
		logcrit("bad ccclose\n");
		return -1;
	}
	if (ss->ssout != NULL)
		(void) fclose(ss->ssout);
	if (ss->ssnot != NULL)
		(void) fclose(ss->ssnot);
	ss->ssnot = NULL;
	if (ss->sserr != NULL)
		(void) fclose(ss->sserr);
	ss->sserr = NULL;
	if (ss->fd != -1)
		(void) close(ss->fd);
	ss->fd = -1;
	gc_session(ss);
	return 0;
}

struct sess *
tcp4_open(void)
{
	struct sess *ss;
	int fd;

	fd = accept(tcp4_fd, NULL, NULL);
	if (fd < 0) {
		logerr("accept(tcp4): %s\n", strerror(errno));
		return NULL;
	}
	ss = (struct sess *) malloc(sizeof(*ss));
	if (ss == NULL) {
		logerr("malloc(tcp4_open): %s\n", strerror(errno));
		return NULL;
	}
	memset(ss, 0, sizeof(*ss));
	ISC_MAGIC_SET(ss, ISC_SESSION_MAGIC);
	ISC_LIST_INSERT_HEAD(&sslist, ss, chain);
	ss->sstype = &cctcp4;
	ss->generation = session_nextgen();
	ss->fd = fd;
	ss->section = 8;
	ss->ssout = fdopen(fd, "w");
	if (ss->ssout == NULL) {
		logerr("fdopen(out)\n");
		tcp4_close(ss);
		return NULL;
	}
	setlinebuf(ss->ssout);
	ss->sserr = fdopen(dup(fd), "w");
	if (ss->sserr == NULL) {
		logerr("fdopen(err)\n");
		tcp4_close(ss);
		return NULL;
	}
	setlinebuf(ss->sserr);
	return ss;
}

int
tcp4_close(struct sess *ss)
{
	ISC_LIST_REMOVE(ss, chain);
	if (ss->sstype != &cctcp4) {
		logcrit("bad ccclose\n");
		return -1;
	}
	if (ss->ssout != NULL)
		(void) fclose(ss->ssout);
	if (ss->ssnot != NULL)
		(void) fclose(ss->ssnot);
	ss->ssnot = NULL;
	if (ss->sserr != NULL)
		(void) fclose(ss->sserr);
	ss->sserr = NULL;
	if (ss->fd != -1)
		(void) close(ss->fd);
	ss->fd = -1;
	gc_session(ss);
	return 0;
}

struct sess *
tcp6_open(void)
{
	struct sess *ss;
	int fd;

	fd = accept(tcp6_fd, NULL, NULL);
	if (fd < 0) {
		logerr("accept(tcp6): %s\n", strerror(errno));
		return NULL;
	}
	ss = (struct sess *) malloc(sizeof(*ss));
	if (ss == NULL) {
		logerr("malloc(tcp_open): %s\n", strerror(errno));
		return NULL;
	}
	memset(ss, 0, sizeof(*ss));
	ISC_MAGIC_SET(ss, ISC_SESSION_MAGIC);
	ISC_LIST_INSERT_HEAD(&sslist, ss, chain);
	ss->sstype = &cctcp6;
	ss->generation = session_nextgen();
	ss->fd = fd;
	ss->section = 8;
	ss->ssout = fdopen(fd, "w");
	if (ss->ssout == NULL) {
		logerr("fdopen(out)\n");
		tcp6_close(ss);
		return NULL;
	}
	setlinebuf(ss->ssout);
	ss->sserr = fdopen(dup(fd), "w");
	if (ss->sserr == NULL) {
		logerr("fdopen(err)\n");
		tcp6_close(ss);
		return NULL;
	}
	setlinebuf(ss->sserr);
	return ss;
}

int
tcp6_close(struct sess *ss)
{
	ISC_LIST_REMOVE(ss, chain);
	if (ss->sstype != &cctcp6) {
		logcrit("bad ccclose\n");
		return -1;
	}
	if (ss->ssout != NULL)
		(void) fclose(ss->ssout);
	ss->ssout = NULL;
	if (ss->ssnot != NULL)
		(void) fclose(ss->ssnot);
	ss->ssnot = NULL;
	if (ss->sserr != NULL)
		(void) fclose(ss->sserr);
	if (ss->fd != -1)
		(void) close(ss->fd);
	ss->fd = -1;
	gc_session(ss);
	return 0;
}

void
unix_start(const char *name)
{
	struct sockaddr_un sa;
	size_t len;

	len = strlen(name);
	if ((len == 0) || (len >= sizeof(sa.sun_path))) {
		logcrit("bad socket name \"%s\"\n", name);
		exit(-1);
	}
	unix_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (unix_fd < 0) {
		logerr("socket(unix): %s\n", strerror(errno));
		exit(-1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, name);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(sa.sun_path);
	(void) unlink(name);
	if (bind(unix_fd, (struct sockaddr *) &sa, (socklen_t) len) < 0) {
		logerr("bind(unix): %s\n", strerror(errno));
		exit(1);
	}
	if (listen(unix_fd, 1) < 0) {
		logerr("listen(unix): %s\n", strerror(errno));
		exit(1);
	}
}

void
tcp4_start(void)
{
	struct sockaddr_in sa;
	int on;

	tcp4_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (tcp4_fd < 0) {
		logerr("socket(inet): %s\n", strerror(errno));
		exit(-1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
#ifndef __linux__
	sa.sin_len = sizeof(sa);
#endif
	(void) inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	sa.sin_port = htons((uint16_t) aftrport);
	on = 1;
	if (setsockopt(tcp4_fd, SOL_SOCKET, SO_REUSEADDR,
		       &on, sizeof(on)) < 0) {
		logerr("SO_REUSEADDR(inet): %s\n", strerror(errno));
		exit(-1);
	}
	if (bind(tcp4_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		logerr("bind(inet): %s\n", strerror(errno));
		exit(1);
	}
	if (listen(tcp4_fd, 1) < 0) {
		logerr("listen(inet): %s\n", strerror(errno));
		exit(1);
	}
}

void
tcp6_start(void)
{
	struct sockaddr_in6 sa;
	int on;

	tcp6_fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (tcp6_fd < 0) {
		logerr("socket(inet6): %s\n", strerror(errno));
		return;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
#ifndef __linux__
	sa.sin6_len = sizeof(sa);
#endif
	(void) inet_pton(AF_INET6, "::1", &sa.sin6_addr);
	sa.sin6_port = htons((uint16_t) aftrport);
	on = 1;
	if (setsockopt(tcp6_fd, SOL_SOCKET, SO_REUSEADDR,
		       &on, sizeof(on)) < 0) {
		logerr("SO_REUSEADDR(inet6): %s\n", strerror(errno));
		exit(-1);
	}
	if (bind(tcp6_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		logerr("bind(inet6): %s\n", strerror(errno));
		(void) close(tcp6_fd);
		tcp6_fd = -1;
	}
	if (listen(tcp6_fd, 1) < 0) {
		logerr("listen(inet6): %s\n", strerror(errno));
		(void) close(tcp6_fd);
		tcp6_fd = -1;
	}
}

void
sess_closeall(const char *name)
{
	struct sess *ss;

	while ((ss = ISC_LIST_FIRST(&sslist)) != NULL)
		(void) ss->sstype->ccclose(ss);
	if (tcp4_fd != -1)
		(void) close(tcp4_fd);
	tcp4_fd = -1;
	if (tcp6_fd != -1)
		(void) close(tcp6_fd);
	tcp6_fd = -1;
	if (unix_fd != -1) {
		(void) close(unix_fd);
		(void) unlink(name);
	}
	unix_fd = -1;
}

/*
 * Packet utils
 */

/* Compute checksum */

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
	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum += sum >> 16;
	return (0xffff & ~sum);
}

int
pseudo_cksum(u_char *p, u_char *pl, u_int l)
{
	int sum;
	u_char saved[4];

	memcpy(saved, p + 8, 4);
	p[8] = 0;
	p[10] = pl[0];
	p[11] = pl[1];
	sum = in_cksum(p + 8, l - 8);
	memcpy(p + 8, saved, 4);
	return sum;
}

int
pseudo6_cksum(void)
{
	int sum;
	u_int l;
	u_char saved[8];

	memcpy(saved, buf6, 8);
	l = len - IP6HDRLEN;
	buf6[0] = l >> 24;
	buf6[1] = (l >> 16) & 0xff;
	buf6[2] = (l >> 8) & 0xff;
	buf6[3] = l & 0xff;
	buf6[4] = buf6[5] = buf6[6] = 0;
	buf6[7] = saved[IP6PROTO];
	sum = in_cksum(buf6, len);
	memcpy(buf6, saved, 8);
	return sum;
}

/* Apply RFC 1624 HC' = ~(~HC + ~m + m') */

void
fix_cksum(u_char *psum,
	  u_char *oaddr, u_char *naddr,
	  u_char *oport, u_char *nport)
{
	int sum;
	int m;

	sum = psum[0] << 8;
	sum |= psum[1];
	sum = ~sum & 0xffff;
	if ((oaddr != NULL) && (memcmp(oaddr, naddr, 4) != 0)) {
		m = oaddr[0] << 8;
		m |= oaddr[1];
		m += oaddr[2] << 8;
		m += oaddr[3];
		m = (m >> 16) + (m & 0xffff);
		sum += m ^ 0xffff;
		m = naddr[0] << 8;
		m |= naddr[1] & 0xff;
		m += naddr[2] << 8;
		m += naddr[3] & 0xff;
		sum += m;
	}
	if ((oport != NULL) && (memcmp(oport, nport, 2) != 0)) {
		m = oport[0] << 8;
		m |= oport[1];
		sum += m ^ 0xffff;
		m = nport[0] << 8;
		m |= nport[1];
		sum += m;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	sum = ~sum & 0xffff;
	psum[0] = sum >> 8;
	psum[1] = sum & 0xff;
}

void
fix_msscksum(u_char *psum, u_char *pmss, u_short newmss)
{
	int sum;
	int m;

	logdebug(10, "fix_msscksum");

	sum = psum[0] << 8;
	sum |= psum[1];
	sum = ~sum & 0xffff;
	m = pmss[0] << 8;
	m |= pmss[1];
	m = (m >> 16) + (m & 0xffff);
	sum += m ^ 0xffff;
	pmss[0] = newmss >> 8;
	pmss[1] = newmss;
	m = pmss[0] << 8;
	m |= pmss[1];
	sum += m;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	sum = ~sum & 0xffff;
	psum[0] = sum >> 8;
	psum[1] = sum & 0xff;
}

void
fix_ftpsacksum(u_char *psum, u_char *psa, int seqack, struct ftpseq *fs)
{
	int sum;
	uint32_t s0, s;

	logdebug(10, "fix_ftpsacksum");

	s0 = psa[0] << 24;
	s0 |= psa[1] << 16;
	s0 |= psa[2] << 8;
	s0 |= psa[3];

	while (fs != NULL) {
		if (seqack == 0) {
			if ((int)(s0 - fs->oldseq) >= 0)
				break;
			fs = ISC_SLIST_NEXT(fs, chain);
		} else {
			if ((int)(s0 - fs->newseq) >= 0)
				break;
			fs = ISC_SLIST_NEXT(fs, chain);
		}
	}
	if (fs == NULL) {
		logdebug(10, "skip fix_ftpsacksum");
		return;
	}

	sum = psum[0] << 8;
	sum |= psum[1];
	sum = ~sum & 0xffff;
	s = ((s0 >> 16) & 0xffff) + (s0 & 0xffff);
	s = (s >> 16) + (s & 0xffff);
	sum += s ^ 0xffff;
	if (seqack == 0)
		s0 += fs->delta;
	else
		s0 -= fs->delta;
	psa[0] = s0 >> 24;
	psa[1] = s0 >> 16;
	psa[2] = s0 >> 8;
	psa[3] = s0 & 0xff;
	s = ((s0 >> 16) & 0xffff) + (s0 & 0xffff);
	sum += s;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	sum = ~sum & 0xffff;
	psum[0] = sum >> 8;
	psum[1] = sum & 0xff;
}	

/* Defrag IPv4 (from tunnel or Internet)
 * This is called on receipt of a fragment.  It reassembles the packet if
 * possible, or stores the fragment for later reassembly.
 * Returns 1 if packet reassembled (in buf4), 0 otherwise.
 */

int
defrag(struct tunnel *t)
{
	struct fragshead *head;
	struct frag *f, *p, *q;
	u_int off;
	u_char more = 0;
	u_short hash;
	int cksum;

	if (t == NULL) {
		logdebug(10, "defrag(out)");
		statsfrout++;

		if (fragsoutcnt >= frag_maxcnt[2]) {
			logdebug(10, "too many IPv4 out fragments");
			statsdropped[DR_FOUTCNT]++;
			return 0;
		}
		head = &fragsout;
	} else {
		logdebug(10, "defrag(in)");
		statsfrgin++;
		if (t->flags & TUNDEBUG)
			debugfrgin++;

		if (fragsincnt >= frag_maxcnt[1]) {
			logdebug(10, "too many IPv4 in fragments");
			statsdropped[DR_FINCNT]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_FINCNT]++;
			return 0;
		} else if (t->frg4cnt >= fragtn_maxcnt[1]) {
			logdebug(10,
				 "too many IPv4 in fragments for tunnel %s",
				 addr2str(AF_INET6, t->remote));
			statsdropped[DR_FINTCNT]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_FINTCNT]++;
			return 0;
		}
		head = &fragsin;
	}

	if (buf4[IPOFFH] & IPMF)
		more = 1;
	len -= IPHDRLEN;
	if (more && (len & 0x7)) {
		logerr("badfrag4\n");
		statsdropped[DR_BADF4]++;
		if ((t != NULL) && (t->flags & TUNDEBUG))
			debugdropped[DR_BADF4]++;
		return 0;
	}
	off = (buf4[IPOFFH] & IPOFFMSK) << 8;
	off |= buf4[IPOFFL];
	off <<= 3;

	tfhlookups++, pfhlookups++;
	hash = jhash_frag();
	hash &= fraghashsz - 1;
	f = fraghash[hash];
	if ((f != NULL) &&
	    (f->tunnel == t) &&
	    (f->buf[IPPROTO] == buf4[IPPROTO]) &&
	    (memcmp(f->buf + IPID, buf4 + IPID, 2) == 0) &&
	    (memcmp(f->buf + IPSRC, buf4 + IPSRC, 8) == 0)) {
		tfhhits++, pfhhits++;
		goto found;
	}
	ISC_TAILQ_FOREACH(f, head, ffragchain) {
		if (f->tunnel != t)
			continue;
		if (f->buf[IPPROTO] != buf4[IPPROTO])
			continue;
		if (memcmp(f->buf + IPID, buf4 + IPID, 2) != 0)
			continue;
		if (memcmp(f->buf + IPSRC, buf4 + IPSRC, 8) == 0)
			break;
	}
	if (f == NULL) {
		f = (struct frag *) malloc(sizeof(*f));
		if (f == NULL) {
			statsdropped[DR_F4MEM]++;
			if ((t != NULL) && (t->flags & TUNDEBUG))
				debugdropped[DR_F4MEM]++;
			return 0;
		}
		memset(f, 0, sizeof(*f));
		ISC_MAGIC_SET(f, ISC_FRAGMENT_MAGIC);
		f->buf = (u_char *) malloc(IPHDRLEN);
		if (f->buf == NULL) {
			statsdropped[DR_F4MEM]++;
			if ((t != NULL) && (t->flags & TUNDEBUG))
				debugdropped[DR_F4MEM]++;
			ISC_MAGIC_FREE(f, ISC_FRAGMENT_MAGIC);
			free(f);
			return 0;
		}
		memcpy(f->buf, buf4, IPHDRLEN);
		f->len = IPHDRLEN;
		f->off = off;
		f->more = more;
		f->expire = seconds + frag_lifetime;
		f->tunnel = t;
		ISC_TAILQ_INSERT_HEAD(head, f, ffragchain);
		if (t != NULL) {
			fragsincnt++;
			t->frg4cnt++;
		} else
			fragsoutcnt++;
	}
	/* don't promote to head because of timeouts */
	f->hash = hash;
	fraghash[hash] = f;
    found:
	for (p = NULL, q = ISC_SLIST_FIRST(&f->fraglist);
	     q != NULL;
	     p = q, q = ISC_SLIST_NEXT(q, fragchain)) {
		if (q->off == off)
			return 0;
		if (q->off > off)
			break;
		if (!q->more)
			return 0;
	}
	if (((q != NULL) && (off + len > q->off)) ||
	    ((q != NULL) && !more) ||
	    ((p != NULL) && (p->off + p->len > off)))
		return 0;
	q = (struct frag *) malloc(sizeof(*q));
	if (q == NULL) {
		statsdropped[DR_F4MEM]++;
		if ((t != NULL) && (t->flags & TUNDEBUG))
			debugdropped[DR_F4MEM]++;
		return 0;
	}
	memset(q, 0, sizeof(*q));
	ISC_MAGIC_SET(q, ISC_FRAGMENT_MAGIC);
	q->buf = (u_char *) malloc(len);
	if (q->buf == NULL) {
		statsdropped[DR_F4MEM]++;
		if ((t != NULL) && (t->flags & TUNDEBUG))
			debugdropped[DR_F4MEM]++;
		ISC_MAGIC_FREE(q, ISC_FRAGMENT_MAGIC);
		free(q);
		return 0;
	}
	memcpy(q->buf, buf4 + IPHDRLEN, len);
	q->len = len;
	q->off = off;
	q->more = more;
	if (p != NULL)
		ISC_SLIST_INSERT_AFTER(p, q, fragchain);
	else {
		if ((off == 0) && (f->off != 0)) {
			memcpy(f->buf, buf4, IPHDRLEN);
			f->off = off;
			f->more = more;
		}
		ISC_SLIST_INSERT_HEAD(&f->fraglist, q, fragchain);
	}

	if (f->off != 0)
		return 0;
	off = 0;
	for (p = NULL, q = ISC_SLIST_FIRST(&f->fraglist);
	     q != NULL;
	     p = q, q = ISC_SLIST_NEXT(q, fragchain)) {
		if (q->off != off)
			return 0;
		off += q->len;
	}
	if ((p == NULL) || p->more)
		return 0;
	len = off + IPHDRLEN;
	if (len > IPMAXLEN) {
		statsdropped[DR_BADF4]++;
		if ((t != NULL) && (t->flags & TUNDEBUG))
			debugdropped[DR_BADF4]++;
		del_frag4(f);
		return 0;
	}

	memcpy(buf4, f->buf, IPHDRLEN);
	buf4[IPOFFH] &= ~(IPDF|IPMF);
	ISC_SLIST_FOREACH(p, &f->fraglist, fragchain)
		memcpy(buf4 + IPHDRLEN + p->off, p->buf, p->len);
	buf4[IPLENH] = len >> 8;
	buf4[IPLENL] = len & 0xff;
	buf4[IPCKSUMH] = buf4[IPCKSUML] = 0;
	cksum = in_cksum(buf4, IPHDRLEN);
	buf4[IPCKSUMH] = cksum >> 8;
	buf4[IPCKSUML] = cksum & 0xff;
	del_frag4(f);

	logdebug(10, "reassembled IPv4 packet");
	if (t != NULL) {
		statsreasin++;
		if (t->flags & TUNDEBUG)
			debugreasin++;
	} else
		statsreasout++;

	return 1;
}

/* Defrag IPv6 (from tunnel)
 * This is called on receipt of a fragment.  It reassembles the packet if
 * possible, or stores the fragment for later reassembly.
 * Returns 1 if packet reassembled (in buf6), 0 otherwise.
 */

int
defrag6(struct tunnel *t)
{
	struct frag *f, *p, *q;
	u_int off;
	u_char more = 0;

	logdebug(10, "defrag6");
	statsfrgin6++;
	if (t->flags & TUNDEBUG)
		debugfrgin6++;

	if (frags6cnt >= frag_maxcnt[0]) {
		logdebug(10, "too many IPv6 fragments");
		statsdropped[DR_F6CNT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_F6CNT]++;
		return 0;
	} else if (t->frg6cnt >= fragtn_maxcnt[0]) {
		logdebug(10, "too many IPv6 fragments for tunnel %s",
			 addr2str(AF_INET6, t->remote));
		statsdropped[DR_F6TCNT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_F6TCNT]++;
		return 0;
	}

	if (buf6[IP6FOFFL] & IP6FMF)
		more = 1;
	len -= IP6FLEN;
	if (more && (len & 0x7)) {
		logerr("badfrag6\n");
		statsdropped[DR_BADF6]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADF6]++;
		return 0;
	}
	off = buf6[IP6FOFFH] << 8;
	off |= buf6[IP6FOFFL] & IP6FMSK;

	ISC_TAILQ_FOREACH(f, &frags6, ffragchain) {
		if (f->tunnel != t)
			continue;
		if (f->buf[IP6FPROTO] != buf6[IP6FPROTO])
			continue;
		/* matching tunnel == matching addresses */
		if (memcmp(f->buf + IP6FID, buf6 + IP6FID, 4) == 0)
			break;
	}
	if (f == NULL) {
		f = (struct frag *) malloc(sizeof(*f));
		if (f == NULL) {
			statsdropped[DR_F6CNT]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_F6CNT]++;
			return 0;
		}
		memset(f, 0, sizeof(*f));
		ISC_MAGIC_SET(f, ISC_FRAGMENT_MAGIC);
		f->buf = (u_char *) malloc(IP6FLEN);
		if (f->buf == NULL) {
			statsdropped[DR_F6CNT]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_F6CNT]++;
			ISC_MAGIC_FREE(f, ISC_FRAGMENT_MAGIC);
			free(f);
			return 0;
		}
		memcpy(f->buf, buf6, IP6FLEN);
		f->len = IP6FLEN;
		f->off = off;
		f->more = more;
		f->expire = seconds + frag_lifetime;
		f->tunnel = t;
		ISC_TAILQ_INSERT_HEAD(&frags6, f, ffragchain);
		frags6cnt++;
		t->frg6cnt++;
	}
	/* don't promote to head because of timeouts */
	for (p = NULL, q = ISC_SLIST_FIRST(&f->fraglist);
	     q != NULL;
	     p = q, q = ISC_SLIST_NEXT(q, fragchain)) {
		if (q->off == off)
			return 0;
		if (q->off > off)
			break;
		if (!q->more)
			return 0;
	}
	if (((q != NULL) && (off + len > q->off)) ||
	    ((q != NULL) && !more) ||
	    ((p != NULL) && (p->off + p->len > off)))
		return 0;
	q = (struct frag *) malloc(sizeof(*q));
	if (q == NULL) {
		statsdropped[DR_F6CNT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_F6CNT]++;
		return 0;
	}
	memset(q, 0, sizeof(*q));
	ISC_MAGIC_SET(q, ISC_FRAGMENT_MAGIC);
	q->buf = (u_char *) malloc(len);
	if (q->buf == NULL) {
		statsdropped[DR_F6CNT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_F6CNT]++;
		ISC_MAGIC_FREE(q, ISC_FRAGMENT_MAGIC);
		free(q);
		return 0;
	}
	memcpy(q->buf, buf6 + IP6FLEN, len);
	q->len = len;
	q->off = off;
	q->more = more;
	if (p != NULL)
		ISC_SLIST_INSERT_AFTER(p, q, fragchain);
	else {
		if ((off == 0) && (f->off != 0)) {
			memcpy(f->buf, buf6, IP6FLEN);
			f->off = off;
			f->more = more;
		}
		ISC_SLIST_INSERT_HEAD(&f->fraglist, q, fragchain);
	}

	if (f->off != 0)
		return 0;
	off = 0;
	for (p = NULL, q = ISC_SLIST_FIRST(&f->fraglist);
	     q != NULL;
	     p = q, q = ISC_SLIST_NEXT(q, fragchain)) {
		if (q->off != off)
			return 0;
		off += q->len;
	}
	if ((p == NULL) || p->more)
		return 0;
	len = off;
	if (len > IPMAXLEN) {
		del_frag6(f);
		statsdropped[DR_BADF6]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADF6]++;
		return 0;
	}

	memcpy(buf6, f->buf, IP6HDRLEN);
	ISC_SLIST_FOREACH(p, &f->fraglist, fragchain)
		memcpy(buf6 + IP6HDRLEN + p->off, p->buf, p->len);
	buf6[IP6LENH] = len >> 8;
	buf6[IP6LENL] = len & 0xff;
	buf6[IP6PROTO] = f->buf[IP6FPROTO];
	len += IP6HDRLEN;
	del_frag6(f);

	logdebug(10, "reassembled IPv6 packet");
	statsreas6++;
	if (t->flags & TUNDEBUG)
		debugreas6++;

	return 1;
}

/* patch TCP MSS */

void
patch_tcpmss(struct tunnel *t)
{
	u_int hl, i, found = 0;
	u_short mss;

	/* is patching enabled? */
	if ((t->flags & TUNMSSFLG) == 0)
		return;
	/* need SYN flag */
	if ((buf4[TCPFLAGS] & TCPFSYN) == 0)
		return;
	hl = (buf4[TCPOFF] & TCPOFFMSK) >> 2;
	/* no data */
	if (hl + IPHDRLEN != len)
		return;
	/* but some options */
	if (hl <= TCPHDRLEN)
		return;
	/* scan option */
	i = IPHDRLEN + TCPHDRLEN;
	while (i < len) {
		if (buf4[i] == TCPOPTEOL) {
			if (found == 0)
				loginfo("no TCP MSS\n");
			break;
		}
		if (buf4[i] == TCPOPTNOP) {
			i++;
			continue;
		}
		if (i + 2 > len) {
			logerr("TCP options overrun0\n");
			return;
		}
		if (buf4[i + 1] < 2) {
			logerr("bad TCP option length\n");
			return;
		}
		if (i + buf4[i + 1] > len) {
			logerr("TCP option overrun\n");
			return;
		}
		if (buf4[i] == TCPOPTMD5) {
			loginfo("TCP MD5\n");
			return;
		}
		if (buf4[i] == TCPOPTMSS) {
			if (found != 0)
				logerr("duplicate TCP MSS\n");
			else
				found = i;
		}
		i += buf4[i + 1];
	}
	if (found == 0) {
		logwarning("no TCP MSS (after scan)\n");
		return;
	}
	i = found;
	if (buf4[i + 1] != TCPOPTMSSLEN) {
		logerr("bad TCP MSS option length\n");
		return;
	}
	i += 2;
	mss = buf4[i] << 8;
	mss |= buf4[i + 1];
	statstcpmss++;
	if (t->flags & TUNDEBUG)
		debugtcpmss++;
	/* no patch needed */
	if ((mss + IPHDRLEN + TCPHDRLEN) <= (t->mtu - IP6HDRLEN))
		return;
	fix_msscksum(buf4 + TCPCKSUMH, buf4 + i,
		     t->mtu - (IP6HDRLEN + IPHDRLEN + TCPHDRLEN));
	statsmsspatched++;
	if (t->flags & TUNDEBUG)
		debugmsspatched++;
}

/* detect TCP closing (from tunnel) */

int
tcpstate_in(struct nat *n)
{
	if (n->timeout == 0)
		return 0;
	if ((n->tcpst == TCP_DEFAULT) && (buf4[TCPFLAGS] & TCPFACK))
		n->tcpst = TCP_ACKED;
	if ((buf4[TCPFLAGS] & (TCPFFIN|TCPFRST)) == 0)
		return 0;
	if (buf4[TCPFLAGS] & TCPFRST)
		n->tcpst |= TCP_CLOSED_BOTH;
	else if (n->tcpst & TCP_CLOSED_IN)
		return 0;
	else
		n->tcpst |= TCP_CLOSED_IN;
	if ((n->tcpst & TCP_CLOSED_OUT) == 0)
		return 0;
	logdebug(10, "tcpstate_in changes lifetime");
	if (buf4[TCPFLAGS] & TCPFRST) {
		if (n->tcpst & TCP_ACKED)
			n->lifetime = nat_lifetime[3];
		else
			n->lifetime = nat_lifetime[4];
	} else
		n->lifetime = nat_lifetime[1];
	if (n->timeout <= seconds + (time_t) n->lifetime)
		return 0;
	n->timeout = seconds + n->lifetime;
	nat_heap_increased(n->heap_index);
	return 1;
}

/* detect TCP closing (from Internet) */

int
tcpstate_out(struct nat *n)
{
	if (n->timeout == 0)
		return 0;
	if ((n->tcpst == TCP_DEFAULT) && (buf4[TCPFLAGS] & TCPFACK))
		n->tcpst = TCP_ACKED;
	if ((buf4[TCPFLAGS] & (TCPFFIN|TCPFRST)) == 0)
		return 0;
	if (buf4[TCPFLAGS] & TCPFRST)
		n->tcpst |= TCP_CLOSED_BOTH;
	else if (n->tcpst & TCP_CLOSED_OUT)
		return 0;
	else
		n->tcpst |= TCP_CLOSED_OUT;
	if ((n->tcpst & TCP_CLOSED_IN) == 0)
		return 0;
	logdebug(10, "tcpstate_out changes lifetime");
	if (buf4[TCPFLAGS] & TCPFRST) {
		if (n->tcpst & TCP_ACKED)
			n->lifetime = nat_lifetime[3];
		else
			n->lifetime = nat_lifetime[4];
	} else
		n->lifetime = nat_lifetime[1];
	if (n->timeout <= seconds + (time_t) n->lifetime)
		return 0;
	n->timeout = seconds + n->lifetime;
	nat_heap_increased(n->heap_index);
	return 1;
}

/* Get the NAT entry for FTP DATA */

struct nat *
get_ftptempdata(struct nat *n0, u_char *np)
{
	struct nat *n;

	logdebug(10, "get_ftptempdata");

	ISC_LIST_FOREACH(n, &n0->xlist, xchain)
		if ((n->sport[0] == np[0]) && (n->sport[1] == np[1]))
			break;
	if (n != NULL)
		return n;

	if (n0->tunnel->tnatcnt[TCPPR] >= maxtnatcnt[TCPPR]) {
		logdebug(10, "too many nat entries(get_ftptempdata)");
		statsdropped[DR_NATCNT]++;
		if (n0->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NATCNT]++;
		return NULL;
	}
	if (n0->tunnel->lastnat != seconds) {
		n0->tunnel->lastnat = seconds;
		n0->tunnel->tnatrt[TCPPR] = 1;
		n0->tunnel->tnatrt[UDPPR] = 0;
		n0->tunnel->tnatrt[ICMPPR] = 0;
	} else {
		n0->tunnel->tnatrt[TCPPR] += 1;
		if (n0->tunnel->tnatrt[TCPPR] >= maxtnatrt[TCPPR]) {
			logdebug(10,
				 "nat creation rate limit(get_ftptempdata)");
			statsdropped[DR_NATRT]++;
			if (n0->tunnel->flags & TUNDEBUG)
				debugdropped[DR_NATRT]++;
			return NULL;
		}
	}

	n = (struct nat *) malloc(sizeof(*n));
	if (n == NULL) {
		logerr("malloc(get_ftptempdata): %s\n", strerror(errno));
		statsdropped[DR_NEWNAT]++;
		if (n0->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NEWNAT]++;
		return NULL;
	}
	memset(n, 0, sizeof(*n));
	ISC_MAGIC_SET(n, ISC_NAT_MAGIC);
	n->tunnel = n0->tunnel;
	n->proto = n0->proto;
	memcpy(n->src, n0->src, 4);
	memcpy(n->nsrc, n0->nsrc, 4);
	memcpy(n->sport, np, 2);
	memcpy(n->dst, n0->dst, 4);
	n->flags = ALL_DST | MATCH_PORT | FTP_DATA;
	n->timeout = seconds + nat_lifetime[1];
	n->lifetime = nat_lifetime[0];
	if (!new_nat(n)) {
		statsdropped[DR_NEWNAT]++;
		if (n0->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NEWNAT]++;
		return NULL;
	}
	ISC_LIST_INSERT_HEAD(&n0->xlist, n, xchain);
	logdebug(10, "get_ftptempdata got %lx", (u_long) n);
	return n;
}

/* Patch a FTP command in a packet */

struct nat *
patch_ftpcmd(struct nat *n, char *cmd)
{
	struct ftpseq *fs, *tfs;
	u_int off, l, i;
	int delta, cksum;
	uint32_t seq;
	u_char tlen[2];

	logdebug(10, "patch_ftpcmd");

	/* remove checksum check when done before */
	tlen[0] = (len - IPHDRLEN) >> 8;
	tlen[1] = (len - IPHDRLEN) & 0xff;
	if (pseudo_cksum(buf4, tlen, len) != 0) {
		logerr("checksum(patch_ftpcmd)\n");
		return NULL;
	}

	off = IPHDRLEN + ((buf4[TCPOFF] & TCPOFFMSK) >> 2);
	l = strlen(cmd);
	delta = l - (len - off);
	memcpy(buf4 + off, cmd, l);
	len += delta;
	buf4[IPLENH] = len >> 8;
	buf4[IPLENL] = len & 0xff;
	buf4[IPCKSUMH] = buf4[IPCKSUML] = 0;
	cksum = in_cksum(buf4, IPHDRLEN);
	buf4[IPCKSUMH] = cksum >> 8;
	buf4[IPCKSUML] = cksum & 0xff;
	buf4[TCPCKSUMH] = buf4[TCPCKSUML] = 0;
	tlen[0] = (len - IPHDRLEN) >> 8;
	tlen[1] = (len - IPHDRLEN) & 0xff;
	cksum = pseudo_cksum(buf4, tlen, len);
	buf4[TCPCKSUMH] = cksum >> 8;
	buf4[TCPCKSUML] = cksum & 0xff;

	seq = buf4[TCPSEQ] << 24;
	seq |= buf4[TCPSEQ + 1] << 16;
	seq |= buf4[TCPSEQ + 2] << 8;
	seq |= buf4[TCPSEQ + 3];
	seq += len - off;
	/* already recorded? */
	if (!ISC_SLIST_EMPTY(&n->ftpseq) &&
	    ((int) (ISC_SLIST_FIRST(&n->ftpseq)->oldseq - seq) >= 0)) {
		logdebug(10, "already recorded");
		return n;
	}
	/* keep at most three records */
	i = 0;
	ISC_SLIST_FOREACH_SAFE(fs, &n->ftpseq, chain, tfs)
		if (i++ > 2) {
			ISC_SLIST_REMOVE(&n->ftpseq, fs, ftpseq, chain);
			ISC_MAGIC_FREE(fs, ISC_FTPSEQ_MAGIC);
			free(fs);
		}
	fs = (struct ftpseq *) malloc(sizeof(*fs));
	if (fs == NULL) {
		logerr("malloc(patch_ftpcmd): %s\n", strerror(errno));
		return NULL;
	}
	memset(fs, 0, sizeof(*fs));
	ISC_MAGIC_SET(fs, ISC_FTPSEQ_MAGIC);
	fs->delta = delta;
	if (!ISC_SLIST_EMPTY(&n->ftpseq))
		fs->delta += ISC_SLIST_FIRST(&n->ftpseq)->delta;
	fs->oldseq = seq;
	fs->newseq = seq + delta;
	ISC_SLIST_INSERT_HEAD(&n->ftpseq, fs, chain);
	return n;
}

/* FTP ALG scan routine */

int
ftpscan(u_char *d, char *pat, int mode, u_char *p, u_short *ps)
{
	char *head = pat, *cmd = (char *) d;
	u_int l;

	/* pattern pat = head "*" tail */
	pat = strchr(head, '*');
	if (pat == NULL)
		return 0;
	*pat++ = '\0';
	l = strlen(head);
	if (strncmp(cmd, head, l) != 0)
		return 0;
	cmd += l - 1;
	cmd = strrchr(cmd, ' ');
	if (cmd == NULL)
		return 0;
	/* result in u_char p[2] (mode == 0) or u_short &ps (mode == 1) */
	if (mode == 0)
		return sscanf(cmd, pat, p, p + 1);
	else
		return sscanf(cmd, pat, ps);
}

/* Patch FTP packet from tunnel to Internet */

struct nat *
patch_ftpin(struct nat *n0, int way, int *reason)
{
	struct nat *td, *n = n0;
	char pat[128];
	u_int off;
	u_short ps;
	u_char p[2];

	logdebug(10, "patch_ftpin%d %lx", way, (u_long) n);

	off = IPHDRLEN + ((buf4[TCPOFF] & TCPOFFMSK) >> 2);
	buf4[len] = '\0';
	memset(pat, 0, 128);
	/* client (0) or server (1) behind the NAT */
	if (way == 0) {
		if (!ISC_SLIST_EMPTY(&n->ftpseq))
			fix_ftpsacksum(buf4 + TCPCKSUMH, buf4 + TCPSEQ,
				       0, ISC_SLIST_FIRST(&n->ftpseq));
		if ((len - off) > 128)
			return n;
		snprintf(pat, 128,
			 "PORT * %u,%u,%u,%u,%%hhu,%%hhu\r\n",
			 n->src[0], n->src[1], n->src[2], n->src[3]);
		if (ftpscan(buf4 + off, pat, 0, p, &ps) == 2) {
			statsftpport++;
			if (n->tunnel->flags & TUNDEBUG)
				debugftpport++;
			td = get_ftptempdata(n, p);
			if (td == NULL) {
				/* get_ftptempdata() marks the drop reason */
				*reason = 1;
				return NULL;
			}
			snprintf(pat, 128,
				 "PORT %u,%u,%u,%u,%u,%u\r\n",
				 td->nsrc[0], td->nsrc[1],
				 td->nsrc[2], td->nsrc[3],
				 td->nport[0], td->nport[1]);
			n = patch_ftpcmd(n, pat);
			return n;
		}
		snprintf(pat, 128,
			 "EPRT * |1|%u.%u.%u.%u|%%hu|\r\n",
			 n->src[0], n->src[1], n->src[2], n->src[3]);
		if (ftpscan(buf4 + off, pat, 1, p, &ps) == 1) {
			statsftpeprt++;
			if (n->tunnel->flags & TUNDEBUG)
				debugftpeprt++;
			td = get_ftptempdata(n, p);
			if (td == NULL) {
				/* get_ftptempdata() marks the drop reason */
				*reason = 1;
				return NULL;
			}
			ps = td->nport[0] << 8;
			ps |= td->nport[1];
			snprintf(pat, 128,
				 "EPRT |1||%u.%u.%u.%u|%u|\r\n",
				 td->nsrc[0], td->nsrc[1],
				 td->nsrc[2], td->nsrc[3], ps);
			n = patch_ftpcmd(n, pat);
			return n;
		}
	} else {
		if (n0->flags & ALL_DST) {
			ISC_LIST_FOREACH(n, &n0->xlist, xchain) {
				if ((memcmp(buf4 + IPDST, n->dst, 4) == 0) &&
				    (memcmp(buf4 + IPDPORT, n->dport, 2) == 0))
					break;
			}
			if (n == NULL) {
				logerr("orphan FTP server packet\n");
				return NULL;
			}
		}
		if (!ISC_SLIST_EMPTY(&n->ftpseq))
			fix_ftpsacksum(buf4 + TCPCKSUMH, buf4 + TCPSEQ,
				       0, ISC_SLIST_FIRST(&n->ftpseq));
		if ((len - off) > 128)
			return n;
		snprintf(pat, 128,
			 "227 * (%u,%u,%u,%u,%%hhu,%%hhu)\r\n",
			 n->src[0], n->src[1], n->src[2], n->src[3]);
		if (ftpscan(buf4 + off, pat, 0, p, &ps) == 2) {
			statsftp227++;
			if (n->tunnel->flags & TUNDEBUG)
				debugftp227++;
			td = get_ftptempdata(n, p);
			if (td == NULL) {
				/* get_ftptempdata() marks the drop reason */
				*reason = 1;
				return NULL;
			}
			snprintf(pat, 128,
				 "227 Entering Passive Mode "
				 "(%u,%u,%u,%u,%u,%u)\r\n",
				 td->nsrc[0], td->nsrc[1],
				 td->nsrc[2], td->nsrc[3],
				 td->nport[0], td->nport[1]);
			n = patch_ftpcmd(n, pat);
			return n;
		}
		strcpy(pat, "229 * (|||%hu|\r\n");
		if (ftpscan(buf4 + off, pat, 1, p, &ps) == 1) {
			statsftp229++;
			if (n->tunnel->flags & TUNDEBUG)
				debugftp229++;
			td = get_ftptempdata(n, p);
			if (td == NULL) {
				/* get_ftptempdata() marks the drop reason */
				*reason = 1;
				return NULL;
			}
			ps = td->nport[0] << 8;
			ps |= td->nport[1];
			snprintf(pat, 128,
				 "229 Entering Extended Passive "
				 "Mode (|||%u|)\r\n", ps);
			n = patch_ftpcmd(n, pat);
			return n;
		}
	}
	return n;
}

/*
 * IN: from tunnel to Internet
 */

/* Filter ICMPv4 packets from tunnel */

int
filtericmpin(u_char type4)
{
	u_int l;

	logdebug(10, "filtericmpin");

	if (len < IPMINLEN)
		return 0;
	if (len > ICMPMAXLEN)
		len = ICMPMAXLEN;
	switch (type4) {
	case 3:		/* unreachable */
	case 11:	/* time exceeded */
	case 12:	/* parameter problem */
		break;

	default:
		logdebug(10, "unhandled icmp type %d", (int)type4);
		return 0;
	}
	if (buf4[0] != IP4VNOOP) {
		logerr("byte0(filtericmpin)\n");
		return 0;
	}
	if ((buf4[IPSRC] == 127) || (buf4[IPDST] == 127)) {
		logerr("localnet(filtericmpin)\n");
		return 0;
	}
	if ((buf4[IPSRC] >= 224) || (buf4[IPDST] >= 224)) {
		logerr("multicast(filtericmpin)\n");
		return 0;
	}
	if ((buf4[IPOFFH] & IPOFFMSK) || (buf4[IPOFFL] != 0)) {
		logerr("fragment(filtericmpin)\n");
		return 0;
	}
	if ((buf4[IPPROTO] != IPTCP) && (buf4[IPPROTO] != IPUDP)) {
		logerr("protocol(filtericmpin)\n");
		return 0;
	}
	l = buf4[IPLENH] << 8;
	l |= buf4[IPLENL];
	if (l < IPMINLEN) {
		logerr("short(filtericmpin)\n");
		return 0;
	}
	if (in_cksum(buf4, IPHDRLEN) != 0) {
		logerr("checksum(filtericmpin)\n");
		return 0;
	}
	logdebug(10, "accepted");
	return 1;
}

/* ICMPv4 from tunnel to Internet */

void
naticmpin(struct tunnel *t,
	  u_char type4,
	  u_char code4,
	  uint32_t mtu4,
	  int from6)
{
	struct nat nat0, *n;
	int cksum, cc;
	u_short id;
	u_char pr;

	if (!from6) {
		/* real ICMPv4 */
		logdebug(10, "naticmpin(v4)");
		if ((len < IP2 + IPMINLEN) ||
		    (memcmp(buf4 + IPDST, buf4 + IP2SRC, 4) != 0)) {
			statsdropped[DR_ICMPIN]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_ICMPIN]++;
			return;
		}
		type4 = buf4[ICMPTYPE];
		code4 = buf4[ICMPCODE];
		mtu4 = buf4[ICMPID + 2] << 8;
		mtu4 |= buf4[ICMPID + 3];
		len -= IP2;
		/* save headers */
		memcpy(buf, buf4, IP2);
		memmove(buf4, buf4 + IP2, len);
	} else
		logdebug(10, "naticmpin(v6)");
	if (!filtericmpin(type4)) {
		statsdropped[DR_ICMPIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_ICMPIN]++;
		return;
	}
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = buf4[IPPROTO];
	if (nat0.proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	memcpy(&nat0.src, buf4 + IPDST, 4);
	memcpy(&nat0.sport, buf4 + IPDPORT, 2);
	n = nat_splay_find(pr, &nat0, 0, 0);
	if (n == NULL) {
		logdebug(10, "no nat entry for naticmpin");
		statsdropped[DR_ICMPIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_ICMPIN]++;
		return;
	}
	memmove(buf4 + IP2, buf4, len);
	if (!from6 && (memcmp(n->src, buf + IPSRC, 4) == 0)) {
		/* end-to-end ICMPv4 */
		memcpy(buf4, buf, IP2);
		len += IP2;
		memcpy(buf4 + IPSRC, n->nsrc, 4);
		fix_cksum(buf4 + IPCKSUMH, n->src, n->nsrc, NULL, NULL);
	} else {
		/* transit ICMPv4: build headers */
		memset(buf4, 0, IP2);
		len += IP2;
		buf4[0] = IP4VNOOP;
		buf4[IPLENH] = len >> 8;
		buf4[IPLENL] = len & 0xff;
		id = arc4_getshort();
		memcpy(buf4 + IPID, &id, 2);
		buf4[IPTTL] = 64;
		buf4[IPPROTO] = IPICMP;
		memcpy(buf4 + IPSRC, icmpsrc, 4);
		memcpy(buf4 + IPDST, buf4 + IP2SRC, 4);
		cksum = in_cksum(buf4, IPHDRLEN);
		buf4[IPCKSUMH] = cksum >> 8;
		buf4[IPCKSUML] = cksum & 0xff;
		buf4[ICMPTYPE] = type4;
		buf4[ICMPCODE] = code4;
		if ((type4 == 3) && (code4 == 4)) {
			buf4[ICMPID] = mtu4 >> 24;
			buf4[ICMPID + 1] = (mtu4 >> 16) & 0xff;
			buf4[ICMPID + 2] = (mtu4 >> 8) & 0xff;
			buf4[ICMPID + 3] = mtu4 & 0xff;
		}
	}
	memcpy(buf4 + IP2DST, n->nsrc, 4);
	fix_cksum(buf4 + IP2CKSUMH, n->src, n->nsrc, NULL, NULL);
	if (n->flags & MATCH_PORT) {
		memcpy(buf4 + IP2DPORT, n->nport, 2);
		if (n->proto == IPTCP)
			fix_cksum(buf4 + IP2 + TCPCKSUMH,
				  n->src, n->nsrc,
				  n->sport, n->nport);
		else if ((n->proto == IPUDP) &&
			 ((buf4[IP2 + UDPCKSUMH] != 0) ||
			  (buf4[IP2 + UDPCKSUML] != 0)))
			fix_cksum(buf4 + IP2 + UDPCKSUMH,
				  n->src, n->nsrc,
				  n->sport, n->nport);
	}
	cksum = in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN);
	buf4[ICMPCKSUMH] = cksum >> 8;
	buf4[ICMPCKSUML] = cksum & 0xff;
	/* don't bump timeout or reorder */
	cc = tun_write(AF_INET, buf4, len);
	if (cc < 0)
		logerr("write(icmpin): %s\n", strerror(errno));
	else if (cc != (int) len)
		logerr("short(icmpin)\n");
	else {
		if (from6) {
			statsnaticmpin6++;
			if (t->flags & TUNDEBUG)
				debugnaticmpin6++;
		} else {
			statsnaticmpin4++;
			if (t->flags & TUNDEBUG)
				debugnaticmpin4++;
		}
		statssent4++;
		if (t->flags & TUNDEBUG)
			debugsent4++;
	}
}

/* From tunnel to Internet (source NAT case)
 * Returns 1 if packet successfully translated, 0 otherwise
 */

int
natin(struct tunnel *t)
{
	struct nat nat0, *n;
	int increased = 0, drdone = 0;
	u_int sport, dport;
	u_char pr = 0;

	logdebug(10, "natin");

	/* find an existing nat binding that matches the 5-tuple
	 * { proto, src addr, src port, dst addr, dst port }
	 */
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = buf4[IPPROTO];
	memcpy(&nat0.src, buf4 + IPSRC, 4);
	memcpy(&nat0.dst, buf4 + IPDST, 4);
	switch (buf4[IPPROTO]) {
	case IPTCP:
		memcpy(&nat0.sport, buf4 + IPSPORT, 2);
		memcpy(&nat0.dport, buf4 + IPDPORT, 2);
		nat0.flags = MATCH_PORT;
		pr = TCPPR;
		break;
	case IPUDP:
		memcpy(&nat0.sport, buf4 + IPSPORT, 2);
		memcpy(&nat0.dport, buf4 + IPDPORT, 2);
		nat0.flags = MATCH_PORT;
		pr = UDPPR;
		break;
	case IPICMP:
		memcpy(&nat0.sport, buf4 + ICMPID, 2);
		nat0.flags = MATCH_ICMP;
		pr = ICMPPR;
		break;
	}
	n = nat_splay_find(pr, &nat0, 0, 0);
    got:
	if (n != NULL) {
		/* rewrite the IPv4 header with nat src addr/port */
		memcpy(buf4 + IPSRC, n->nsrc, 4);
		fix_cksum(buf4 + IPCKSUMH, n->src, n->nsrc, NULL, NULL);
		if (n->flags & MATCH_PORT)
			memcpy(buf4 + IPSPORT, n->nport, 2);
		else if (n->flags & MATCH_ICMP)
			memcpy(buf4 + ICMPID, n->nport, 2);
		switch (n->proto) {
		case IPTCP:
			fix_cksum(buf4 + TCPCKSUMH,
				  n->src, n->nsrc,
				  n->sport, n->nport);
			patch_tcpmss(t);
			if ((buf4[IPDPORT] == 0) &&
			    (buf4[IPDPORT + 1] == PORTFTP))
				n = patch_ftpin(n, 0, &drdone);
			else if ((n->sport[0] == 0) &&
				 (n->sport[1] == PORTFTP))
				n = patch_ftpin(n, 1, &drdone);
			if (n == NULL) {
				if (drdone)
					return 0;
				statsdropped[DR_BADIN]++;
				if (t->flags & TUNDEBUG)
					debugdropped[DR_BADIN]++;
				return 0;
			}
			increased = tcpstate_in(n);
			break;

		case IPUDP:
			if ((buf4[UDPCKSUMH] != 0) || (buf4[UDPCKSUML] != 0)) {
				fix_cksum(buf4 + UDPCKSUMH,
					  n->src, n->nsrc,
					  n->sport, n->nport);
			}
			break;
		case IPICMP:
			fix_cksum(buf4 + ICMPCKSUMH,
				  NULL, NULL,
				  n->sport, n->nport);
			break;
		}
		if (n->timeout && !increased &&
		    (seconds + nat_lifetime[4] > n->timeout)) {
			n->timeout = seconds + nat_lifetime[4];
			nat_heap_decreased(n->heap_index);
		}
		if (debuglevel >= 10) {
			sport = (n->sport[0] << 8) | n->sport[1];
			dport = (n->dport[0] << 8) | n->dport[1];
			logdebug(10, "%s %s/%u -> %s/%u",
				 proto2str(n->proto),
				 addr2str(AF_INET, n->src), sport,
				 addr2str(AF_INET, n->dst), dport);
		}
		statsnatin++;
		if (t->flags & TUNDEBUG)
			debugnatin++;
		return 1;
	} else if (t->tnatcnt[pr] >= maxtnatcnt[pr]) {
		logdebug(10, "too many nat entries");
		statsdropped[DR_NATCNT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_NATCNT]++;
		return 0;
	} else if (t->lastnat != seconds) {
		t->lastnat = seconds;
		t->tnatrt[TCPPR] = 0;
		t->tnatrt[UDPPR] = 0;
		t->tnatrt[ICMPPR] = 0;
		t->tnatrt[pr] = 1;
	} else {
		t->tnatrt[pr] += 1;
		if (t->tnatrt[pr] >= maxtnatrt[pr]) {
			logdebug(10, "nat creation rate limit");
			statsdropped[DR_NATRT]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_NATRT]++;
			return 0;
		}
	}

	/* no matching nat binding found, try to create new one */
	n = (struct nat *) malloc(sizeof(*n));
	if (n == NULL) {
		logerr("malloc(nat): %s\n", strerror(errno));
		statsdropped[DR_NEWNAT]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_NEWNAT]++;
		return 0;
	}
	memset(n, 0, sizeof(*n));
	ISC_MAGIC_SET(n, ISC_NAT_MAGIC);
	n->tunnel = t;
	n->timeout = seconds + nat_lifetime[4];
	memcpy(n->src, buf4 + IPSRC, 4);
	memcpy(n->dst, buf4 + IPDST, 4);
	memcpy(n->nsrc, pools[t->srcidx]->addr, 4);
	n->proto = buf4[IPPROTO];
	switch (buf4[IPPROTO]) {
	case IPTCP:
		n->flags = MATCH_PORT;
		memcpy(n->sport, buf4 + IPSPORT, 2);
		memcpy(n->dport, buf4 + IPDPORT, 2);
		n->lifetime = nat_lifetime[0];
		break;

	case IPUDP:
		n->flags = MATCH_PORT;
		memcpy(n->sport, buf4 + IPSPORT, 2);
		memcpy(n->dport, buf4 + IPDPORT, 2);
		n->lifetime = nat_lifetime[2];
		break;

	case IPICMP:
		n->flags = MATCH_ICMP;
		memcpy(n->sport, buf4 + ICMPID, 2);
		n->lifetime = nat_lifetime[3];
		break;
	}
	if (new_nat(n))
		goto got;
	statsdropped[DR_NEWNAT]++;
	if (t->flags & TUNDEBUG)
		debugdropped[DR_NEWNAT]++;
	return 0;
}

/* From tunnel to Internet (PRR/A+P case)
 * This checks the packet against the (statically configured) list of
 * PRR bindings, but does not alter the packet at the exception of TCP MSS.
 * Returns 1 if packet is okay to send, 0 otherwise
 */

int
prrin(struct tunnel *t)
{
	struct nat nat0, *n;
	u_int sport;
	u_char pr = 0;

	logdebug(10, "prrin");

	/* find an existing nat binding that matches the 5-tuple
	 * { proto, src addr, src port, dst addr, dst port }
	 */
	memset(&nat0, 0, sizeof(nat0));
	ISC_MAGIC_SET(&nat0, ISC_NAT_MAGIC);
	nat0.tunnel = t;
	nat0.proto = buf4[IPPROTO];
	nat0.flags = ALL_DST | PRR_NULL;
	memcpy(&nat0.src, buf4 + IPSRC, 4);
	switch (buf4[IPPROTO]) {
	case IPTCP:
		memcpy(&nat0.sport, buf4 + IPSPORT, 2);
		pr = TCPPR;
		break;
	case IPUDP:
		memcpy(&nat0.sport, buf4 + IPSPORT, 2);
		pr = UDPPR;
		break;
	case IPICMP:
		memcpy(&nat0.sport, buf4 + ICMPID, 2);
		pr = ICMPPR;
		break;
	}
	n = nat_splay_find(pr, &nat0, 1, 0);
	if (n != NULL) {
		if (buf4[IPPROTO] == IPTCP)
			patch_tcpmss(t);
		if (debuglevel >= 10) {
			sport = (n->sport[0] << 8) | n->sport[1];
			logdebug(10, "%s %s/%u",
				 proto2str(n->proto),
				 addr2str(AF_INET, n->src), sport);
		}
		statsprrin++;
		if (t->flags & TUNDEBUG)
			debugprrin++;
		return 1;
	}
	logdebug(10, "no nat entry for prrin");
	statsdropped[DR_INGRESS]++;
	if (t->flags & TUNDEBUG)
		debugdropped[DR_INGRESS]++;
	return 0;
}

/* From tunnel to Internet (NO-NAT case)
 * This does not alter the packet at the exception of TCP MSS.
 */

int
nonatin(struct tunnel *t)
{
	const u_char *mask = mask4[t->nnplen];
	int i;

	logdebug(10, "nonatin");

	for (i = 0; i < 4; i++)
		if ((buf4[IPSRC + i] & mask[i]) != t->nnaddr[i]) {
			logdebug(10, "source outside nonat");
			statsdropped[DR_INGRESS]++;
			return 0;
		}

	if (buf4[IPPROTO] == IPTCP)
		patch_tcpmss(t);
	statsnonatin++;
	if (t->flags & TUNDEBUG)
		debugnonatin++;
	return 1;
}

/* ICMPv4 from NO-NAT tunnel to Internet */

void
nonaticmpin(struct tunnel *t,
	    u_char type4,
	    u_char code4)
{
	int cksum, cc;
	u_short id;

	logdebug(10, "nonaticmpin(v6)");
	if (!filtericmpin(type4)) {
		statsdropped[DR_ICMPIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_ICMPIN]++;
		return;
	}
	memmove(buf4 + IP2, buf4, len);
	/* transit ICMPv4: build headers */
	memset(buf4, 0, IP2);
	len += IP2;
	buf4[0] = IP4VNOOP;
	buf4[IPLENH] = len >> 8;
	buf4[IPLENL] = len & 0xff;
	id = arc4_getshort();
	memcpy(buf4 + IPID, &id, 2);
	buf4[IPTTL] = 64;
	buf4[IPPROTO] = IPICMP;
	memcpy(buf4 + IPSRC, icmpsrc, 4);
	memcpy(buf4 + IPDST, buf4 + IP2SRC, 4);
	cksum = in_cksum(buf4, IPHDRLEN);
	buf4[IPCKSUMH] = cksum >> 8;
	buf4[IPCKSUML] = cksum & 0xff;
	buf4[ICMPTYPE] = type4;
	buf4[ICMPCODE] = code4;
	cksum = in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN);
	buf4[ICMPCKSUMH] = cksum >> 8;
	buf4[ICMPCKSUML] = cksum & 0xff;
	cc = tun_write(AF_INET, buf4, len);
	if (cc < 0)
		logerr("write(nonaticmpin): %s\n", strerror(errno));
	else if (cc != (int) len)
		logerr("short(nonaticmpin)\n");
	else {
		statsnaticmpin6++;
		if (t->flags & TUNDEBUG)
			debugnaticmpin6++;
		statssent4++;
		if (t->flags & TUNDEBUG)
			debugsent4++;
	}
}

/* Filter IPv4 packets from tunnel
 * Returns:
 * 0: drop packet
 * 1: perform NAT on packet
 * 2: perform PRR on packet
 * 3: perform NONAT on packet
 */

int
filterin(struct tunnel *t)
{
	u_int l;
#ifdef notyet
	u_char tlen[2];
#endif

    again:
	logdebug(10, "filterin");

	/* sanity checking */
	if (len < IPMINLEN) {
		logerr("length(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	if (buf4[0] != IP4VNOOP) {
		logerr("byte0(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	if ((buf4[IPSRC] == 127) || (buf4[IPDST] == 127)) {
		logerr("localnet(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	if ((buf4[IPSRC] >= 224) || (buf4[IPDST] >= 224)) {
		logerr("multicast(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	if ((buf4[IPPROTO] != IPTCP) &&
	    (buf4[IPPROTO] != IPUDP) &&
	    (buf4[IPPROTO] != IPICMP)) {
		logerr("protocol(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	l = buf4[IPLENH] << 8;
	l |= buf4[IPLENL];
	if ((l < IPMINLEN) || (l > len)) {
		logerr("short(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}
	len = l;
	if (in_cksum(buf4, IPHDRLEN) != 0) {
		logerr("checksum(filterin)\n");
		statsdropped[DR_BADIN]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BADIN]++;
		return 0;
	}

	/* IPv4 fragment */
	if ((buf4[IPOFFH] & (IPMF|IPOFFMSK)) || (buf4[IPOFFL] != 0)) {
		/* if packet can be successfully reassembled,
		 * process it as a new packet
		 */
		if (defrag(t))
			goto again;
		return 0;
	}

	switch (buf4[IPPROTO]) {
	case IPTCP:
#ifdef notyet
		tlen[0] = (len - IPHDRLEN) >> 8;
		tlen[1] = (len - IPHDRLEN) & 0xff;
		if (pseudo_cksum(buf4, tlen, len) != 0) {
			logerr("checksum(TCP,filterin)\n");
			statsdropped[DR_BADIN]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_BADIN]++;
			return 0;
		}
#endif
		break;

	case IPUDP:
#ifdef notyet
		if (((buf4[UDPCKSUMH] != 0) || (buf4[UDPCKSUML] != 0)) &&
		    (pseudo_cksum(buf4, buf4 + UDPLEN, len) != 0)) {
			logerr("checksum(UDP,filterin)\n");
			statsdropped[DR_BADIN]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_BADIN]++;
			return 0;
		}
#endif
		break;

	case IPICMP:
		if (in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN) != 0) {
			logerr("checksum(ICMP,filterin)\n");
			statsdropped[DR_BADIN]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_BADIN]++;
			return 0;
		}
		if (t->flags & TUNNONAT)
			return 3;
		if (buf4[ICMPTYPE] != ICMPECHREQ) {
			naticmpin(t, (u_char) 0, (u_char) 0, 0, 0);
			return 0;
		}
		break;
	}

	if (t->flags & TUNNONAT)
		return 3;

	if (acl4(buf4 + IPSRC))
		return 1;

	/* global IPv4 address -> A+P/PRR */
	return 2;
}

/* Deal with ICMPv6 from tunnel side */

void
icmp6in(void)
{
	struct tunnel *t;
	u_char code4 = 1;
	u_int mtu = 0;

	logdebug(10, "icmp6in");

	if (len < IP6HDRLEN + 8 + IP6HDRLEN + 8) {
		logerr("short(icmp6in)\n");
		statsdropped[DR_BAD6]++;
		return;
	}
	switch (buf6[ICMP6TYPE]) {
	case 1:		/* destination unreachable */
		if (buf6[ICMP6CODE] > 3) {	/* address unreachable */
			statsdropped[DR_ICMP6]++;
			return;
		}
		break;

	case 2:		/* packet too big */
		if (buf6[ICMP6CODE] != 0) {
			statsdropped[DR_ICMP6]++;
			return;
		}
		mtu = buf6[ICMP6PTR] << 24;
		mtu |= buf6[ICMP6PTR + 1] << 16;
		mtu |= buf6[ICMP6PTR + 2] << 8;
		mtu |= buf6[ICMP6PTR + 3];
		if (mtu == 0) {
			logerr("mtu(icmp6in)\n");
			statsdropped[DR_ICMP6]++;
			return;
		}
		break;

	case 3:		/* time exceeded */
		if (buf6[ICMP6CODE] != 0) {
			statsdropped[DR_ICMP6]++;
			return;
		}
		break;

	case 4:		/* parameter problem */
		break;

	default:
		logdebug(10, "unhandled icmp6 type %d", (int)buf6[ICMP6TYPE]);
		statsdropped[DR_ICMP6]++;
		return;
	}
	if (memcmp(buf6 + IP6DST, buf6 + IP62SRC, 16) != 0) {
		logerr("dest(icmp6in)\n");
		statsdropped[DR_ICMP6]++;
		return;
	}
	if ((buf6[IP62PROTO] != IP6IP4) || (len < IP64 + IPMINLEN)) {
		logerr("length(icmp6in)\n");
		statsdropped[DR_ICMP6]++;
		return;
	}
	if ((buf6[IP64PROTO] != IPTCP) && (buf6[IP64PROTO] != IPUDP)) {
		logerr("protocol(icmp6in)\n");
		statsdropped[DR_ICMP6]++;
		return;
	}
	if (pseudo6_cksum() != 0) {
		logerr("checksum(icmp6in)\n");
		statsdropped[DR_ICMP6]++;
		return;
	}
	t = tunnel_lookup(buf6 + IP62DST);
	if (t == NULL) {
		logerr("icmp6in: no tunnel found for %s\n",
		       addr2str(AF_INET6, buf6 + IP62DST));
		statsdropped[DR_NOTUN]++;
		return;
	}
	if (mtu != 0) {
		logdebug(10, "icmp6in: set mtu to %u", mtu);
		(void) set_tunnel_mtu(NULL, t->remote, mtu, 0);
		return;
	}

	/* decapsulate the icmp packet and send it on */
	len -= IP64;
	memcpy(buf4, buf6 + IP64, len);
	if ((t->flags & TUNNONAT) == 0)
		naticmpin(t, (u_char) 3, code4, 0, 1);
	else
		nonaticmpin(t, (u_char) 3, code4);
	return;
}

/* IPv6 ACL filtering (return 0 for drop, 1 for accept) */

int
acl6(u_char *src)
{
	struct acl6 *a;
	u_int i;

	ISC_STAILQ_FOREACH(a, &acl6s, chain) {
		for (i = 0; i < 16; i++)
			if ((src[i] & a->mask[i]) != a->addr[i])
				break;
		if (i == 16)
			return 1;
	}
	logdebug(1, "%s dropped ACL6", addr2str(AF_INET6, src));
	return 0;
}

/* IPv4 ACL filtering (return 0 for reject, 1 for accept) */

int
acl4(u_char *src)
{
	struct acl4 *a;

	ISC_STAILQ_FOREACH(a, &acl4s, chain)
		if (((src[0] & a->mask[0]) == a->addr[0]) &&
		    ((src[1] & a->mask[1]) == a->addr[1]) &&
		    ((src[2] & a->mask[2]) == a->addr[2]) &&
		    ((src[3] & a->mask[3]) == a->addr[3]))
			return 1;
	return 0;
}

/* Decapsulate IPv4 packets from IPv6
 *
 * This copies the encapsulated IPv4 packet from the global IPv6 packet
 * buffer buf6[] to the global IPv4 packet buffer buf4[], and returns the
 * tunnel that the packet belongs to (determined from the source IPv6
 * address).
 */

struct tunnel *
decap(void)
{
	struct tunnel *t = NULL;
	u_int l;
#ifdef notyet
	u_char tos;
#endif

    again:
	logdebug(10, "decap");

	/* sanity checks */
	/* version check is also done in loop1(), but keep it here
	 * for the "again" cases
	 */
	if ((buf6[0] & IPVERMSK) != IP6V) {
		logerr("version(decap)\n");
		statsdropped[DR_BAD6]++;
		return NULL;
	}
	if (len < IP6HDRLEN + 8 + 8) {
		logerr("short(decap)\n");
		statsdropped[DR_BAD6]++;
		return NULL;
	}

	/* deal with icmp packets separately */
	if (buf6[IP6PROTO] == IP6ICMP) {
		if (acl6(buf6 + IP6SRC))
			icmp6in();
		return NULL;
	}

	/* find (or create) the tunnel this belongs to */
	if (t == NULL)
		t = tunnel_lookup(buf6 + IP6SRC);
	if (t == NULL) {
		if (use_autotunnel) {
			if (!acl6(buf6 + IP6SRC)) {
				statsdropped[DR_ACL6]++;
				return NULL;
			}
			t = add_stdtunnel(NULL, buf6 + IP6SRC, NULL);
			if (t == NULL) {
				logerr("failed to create tunnel for %s\n",
				       addr2str(AF_INET6, buf6 + IP6SRC));
				statsdropped[DR_NOTUN]++;
				return NULL;
			}
		} else {
			logerr("no tunnel for %s, and autotunnel disabled\n",
			       addr2str(AF_INET6, buf6 + IP6SRC));
			statsdropped[DR_NOTUN]++;
			return NULL;
		}
	}

	logdebug(3, "decap: got packet, length=%u", len);

	/* sanity checks */
	len -= IP6HDRLEN;
	l = buf6[IP6LENH] << 8;
	l |= buf6[IP6LENL];
	if (l > len) {
		logerr("length (decap)\n");
		statsdropped[DR_BAD6]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BAD6]++;
		return NULL;
	} else if (l < len) {
		if (l < 8 + 8) {
			logerr("short (decap)\n");
			statsdropped[DR_BAD6]++;
			if (t->flags & TUNDEBUG)
				debugdropped[DR_BAD6]++;
			return NULL;
		}
		len = l;
	}

	if (buf6[IP6PROTO] != IP6IP4) {
		/* not an encapsulated IPv4 packet */
		if ((buf6[IP6PROTO] == IP6FRAG) &&
		    (buf6[IP6FPROTO] == IP6IP4)) {
			/* IPv6 fragment of an encapsulated packet */
			len += IP6HDRLEN;
			if (defrag6(t))
				/* if packet can be successfully reassembled,
				 * process it as a new packet
				 */
				goto again;
			return NULL;
		}

		if ((buf6[IP6PROTO] == IP6DSTOP) &&
		    (buf6[IP6FPROTO] == IP6IP4) &&
		    (buf6[IP6FPROTO + 1] == 0)) {
			/*
			 * Destination option header:
			 * likely a Tunnel-Encapsulation-Limit, strip it!
			 */
			l -= 8;
			len -= 8;
			buf6[IP6LENH] = l >> 8;
			buf6[IP6LENL] = l & 0xff;
			buf6[IP6PROTO] = buf6[IP6FPROTO];
			memmove(buf6 + IP6HDRLEN, buf6 + IP6HDRLEN + 8, len);
			len += IP6HDRLEN;
			goto again;
		}

		/* some other IPv6 packet */
		logerr("header6 (decap)\n");
		statsdropped[DR_BAD6]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_BAD6]++;
		return NULL;
	}

	/* copy the payload to the IPv4 packet buffer */
#ifdef notyet
	tos = (buf6[0] & 0x0f) << 4;
	tos |= buf6[1] >> 4;
#endif
	memcpy(buf4, buf6 + IP6HDRLEN, len);

#ifdef notyet
	/* CE and inner != not-ECT and inner != CE -> CE */
	if (((tos & 3) == 3) &&
	    ((buf4[IPTOS] & 3) != 0) &&
	    ((buf4[IPTOS] & 3) != 3)) {
		int cksum;

		if (in_cksum(buf4, IPHDRLEN) != 0)
			return NULL;
		buf4[IPTOS] |= tos & 3;
		buf4[ICMPCKSUMH] = buf4[ICMPCKSUML] = 0;
		cksum = in_cksum(buf4, IPHDRLEN);
		buf4[ICMPCKSUMH] = cksum >> 8;
		buf4[ICMPCKSUML] = cksum & 0xff;
	}
#endif

	return t;
}

/*
 * OUT: from Internet to tunnel
 */

/* Clone a FTP server static binding at the first match */

struct nat *
get_ftptempsrv(struct nat *n0, int *reason)
{
	struct nat *n;

	logdebug(10, "get_ftptempsrv");

	if (n0->tunnel->tnatcnt[TCPPR] >= maxtnatcnt[TCPPR]) {
		logdebug(10, "too many nat entries(get_ftptempsrv)");
		statsdropped[DR_NATCNT]++;
		if (n0->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NATCNT]++;
		*reason = 1;
		return NULL;
	}
	if (n0->tunnel->lastnat != seconds) {
		n0->tunnel->lastnat = seconds;
		n0->tunnel->tnatrt[TCPPR] = 1;
		n0->tunnel->tnatrt[UDPPR] = 0;
		n0->tunnel->tnatrt[ICMPPR] = 0;
	} else {
		n0->tunnel->tnatrt[TCPPR] += 1;
		if (n0->tunnel->tnatrt[TCPPR] >= maxtnatrt[TCPPR]) {
			logdebug(10,
				 "nat creation rate limit(get_ftptempsrv)");
			statsdropped[DR_NATRT]++;
			if (n0->tunnel->flags & TUNDEBUG)
				debugdropped[DR_NATRT]++;
			*reason = 1;
			return NULL;
		}
	}

	n = (struct nat *) malloc(sizeof(*n));
	if (n == NULL) {
		logerr("malloc(get_ftptempsrv): %s\n", strerror(errno));
		statsdropped[DR_NEWNAT]++;
		if (n0->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NEWNAT]++;
		*reason = 1;
		return NULL;
	}
	memset(n, 0, sizeof(*n));
	ISC_MAGIC_SET(n, ISC_NAT_MAGIC);
	n->tunnel = n0->tunnel;
	n->proto = n0->proto;
	memcpy(n->src, n0->src, 4);
	memcpy(n->nsrc, n0->nsrc, 4);
	memcpy(n->sport, n0->sport, 2);
	memcpy(n->nport, n0->nport, 2);
	memcpy(n->dst, buf4 + IPSRC, 4);
	memcpy(n->dport, buf4 + IPSPORT, 2);
	n->flags = MATCH_PORT;
	n->timeout = seconds + nat_lifetime[1];
	n->lifetime = nat_lifetime[0];

	if (!nat_heap_insert(n)) {
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return NULL;
	}
	if (nat_tree_insert(TCPPR, n) != NULL) {
		logcrit("rb collision(get_ftptempsrv)\n");
		nat_heap_delete(n->heap_index);
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return NULL;
	}
	if (nat_splay_insert(TCPPR, n) != NULL) {
		logcrit("splay collision(get_ftptempsrv)\n");
		(void) nat_tree_remove(TCPPR, n);
		nat_heap_delete(n->heap_index);
		ISC_MAGIC_FREE(n, ISC_NAT_MAGIC);
		free(n);
		return NULL;
	}
	ISC_LIST_INSERT_HEAD(&n0->xlist, n, xchain);

	natcntt++;
	n->tunnel->tnatcnt[TCPPR]++;
	statscnat++;
	if (n->tunnel->flags & TUNDEBUG)
		debugcnat++;
#ifdef TRACE_NAT
	trace_nat(n, "add");
#endif
	logdebug(10, "get_ftptempsrv got %lx", (u_long) n);
	return n;
}

/* Patch FTP packet from Internet to tunnel */

struct nat *
patch_ftpout(struct nat *n0, int way, int *reason)
{
	struct nat *n = n0;

	logdebug(10, "patch_ftpout%d %lx", way, (u_long) n);

	if ((way == 1) && (n0->flags & ALL_DST)) {
		ISC_LIST_FOREACH(n, &n0->xlist, xchain) {
			if ((memcmp(buf4 + IPSRC, n->dst, 4) == 0) &&
			    (memcmp(buf4 + IPSPORT, n->dport, 2) == 0))
				break;
		}
		if (n == NULL)
			n = get_ftptempsrv(n0, reason);
		if (n == NULL)
			return NULL;
	}
	if (!ISC_SLIST_EMPTY(&n->ftpseq))
		fix_ftpsacksum(buf4 + TCPCKSUMH, buf4 + TCPACK,
			       1, ISC_SLIST_FIRST(&n->ftpseq));
	return n;
}

/* Too big error on unfragmentable packet from Internet */

void
toobigout(struct nat *n)
{
	int cksum, cc;
	u_short id, mtu;

	logdebug(10, "toobigout");

	if (len > ICMPMAXLEN)
		len = ICMPMAXLEN;
	memmove(buf4 + IP2, buf4, len);
	memset(buf4, 0, IP2);
	len += IP2;
	buf4[0] = IP4VNOOP;
	buf4[IPLENH] = len >> 8;
	buf4[IPLENL] = len & 0xff;
	id = arc4_getshort();
	memcpy(buf4 + IPID, &id, 2);
	buf4[IPTTL] = 64;
	buf4[IPPROTO] = IPICMP;
	memcpy(buf4 + IPSRC, icmpsrc, 4);
	memcpy(buf4 + IPDST, buf4 + IP2SRC, 4);
	cksum = in_cksum(buf4, IPHDRLEN);
	buf4[IPCKSUMH] = cksum >> 8;
	buf4[IPCKSUML] = cksum & 0xff;
	buf4[ICMPTYPE] = 3;
	buf4[ICMPCODE] = 4;
	mtu = n->tunnel->mtu - IP6HDRLEN;
	buf4[ICMPID + 2] = mtu >> 8;
	buf4[ICMPID + 3] = mtu & 0xff;
	cksum = in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN);
	buf4[ICMPCKSUMH] = cksum >> 8;
	buf4[ICMPCKSUML] = cksum & 0xff;

	if (n->timeout && (seconds + (time_t) n->lifetime > n->timeout)) {
		n->timeout = seconds + n->lifetime;
		nat_heap_decreased(n->heap_index);
	}

	cc = tun_write(AF_INET, buf4, len);
	if (cc < 0)
		logcrit("write(toobigout): %s\n", strerror(errno));
	else if (cc != (int) len)
		logcrit("short(toobigout)\n");
	else {
		statstoobig++;
		if (n->tunnel->flags & TUNDEBUG)
			debugtoobig++;
	}
}

/* From Internet to tunnel */

struct tunnel *
natout(void)
{
	struct nat *n, nat0;
	struct nat *nn;
	int increased = 0, drdone = 0;
	u_char pr = 0;

	logdebug(10, "natout");

	memset(&nat0, 0, sizeof(nat0));
	nat0.proto = buf4[IPPROTO];
	memcpy(nat0.nsrc, buf4 + IPDST, 4);
	memcpy(nat0.dst, buf4 + IPSRC, 4);
	switch (nat0.proto) {
	case IPTCP:
		memcpy(nat0.nport, buf4 + IPDPORT, 2);
		memcpy(nat0.dport, buf4 + IPSPORT, 2);
		nat0.flags = MATCH_PORT;
		pr = TCPPR;
		break;
	case IPUDP:
		memcpy(nat0.nport, buf4 + IPDPORT, 2);
		memcpy(nat0.dport, buf4 + IPSPORT, 2);
		nat0.flags = MATCH_PORT;
		pr = UDPPR;
		break;
	case IPICMP:
		memcpy(nat0.nport, buf4 + ICMPID, 2);
		nat0.flags = MATCH_ICMP;
		pr = ICMPPR;
		break;
	}
	n = nat_lookup(pr, &nat0);
	if (n == NULL) {
		logdebug(10, "no nat entry for natout");
		statsdropped[DR_NATOUT]++;
		return NULL;
	}
	if ((n->flags & FTP_DATA) && (memcmp(n->dst, buf4 + IPSRC, 4) != 0)) {
		logdebug(10, "unexpected peer in ftp data");
		statsdropped[DR_NATOUT]++;
		if (n->tunnel->flags & TUNDEBUG)
			debugdropped[DR_NATOUT]++;
		return NULL;
	}
	if ((buf4[IPOFFH] & IPDF) &&
	    (buf4[IPPROTO] != IPICMP) &&
	    ((buf4[IPOFFH] & IPOFFMSK) == 0) &&
	    (buf4[IPOFFL] == 0) &&
	    (len + IP6HDRLEN > (u_int) n->tunnel->mtu)) {
		u_int saved = len;
		u_char tbpol = n->tunnel->flags & (TUNTBDROP | TUNTBICMP);

		if (tbpol == TUNTBICMP)
			memcpy(buf, buf4, len);
		if ((tbpol & TUNTBICMP) != 0)
			toobigout(n);
		if (tbpol == TUNTBICMP)
			memcpy(buf4, buf, saved);
		if ((tbpol & TUNTBDROP) != 0) {
			logdebug(10, "too big dropped");
			statsdropped[DR_TOOBIG]++;
			if (n->tunnel->flags & TUNDEBUG)
				debugdropped[DR_TOOBIG]++;
			return NULL;
		}
	}
	if (n->flags & PRR_NULL) {
		if (buf4[IPPROTO] == IPTCP)
			patch_tcpmss(n->tunnel);
		if (n != n->tunnel->tnat_root[pr])
			nat_splay_splay(pr, n);
		statsprrout++;
		if (n->tunnel->flags & TUNDEBUG)
			debugprrout++;
		return n->tunnel;
	}
	memcpy(buf4 + IPDST, n->src, 4);
	fix_cksum(buf4 + IPCKSUMH, n->nsrc, n->src, NULL, NULL);
	if (n->flags & MATCH_PORT)
		memcpy(buf4 + IPDPORT, n->sport, 2);
	else if (n->flags & MATCH_ICMP)
		memcpy(buf4 + ICMPID, n->sport, 2);
	switch (n->proto) {
	case IPTCP:
		fix_cksum(buf4 + TCPCKSUMH,
			  n->nsrc, n->src,
			  n->nport, n->sport);
		patch_tcpmss(n->tunnel);
		if ((buf4[IPSPORT] == 0) && (buf4[IPSPORT + 1] == PORTFTP))
			nn = patch_ftpout(n, 0, &drdone);
		else if ((n->sport[0] == 0) && (n->sport[1] == PORTFTP))
			nn = patch_ftpout(n, 1, &drdone);
		else
			nn = n;
		if (nn == NULL) {
			if (drdone)
				return NULL;
			statsdropped[DR_NATOUT]++;
			if (n->tunnel->flags & TUNDEBUG)
				debugdropped[DR_NATOUT]++;
			return NULL;
		} else
			n = nn;
		increased = tcpstate_out(n);
		break;

	case IPUDP:
		if ((buf4[UDPCKSUMH] != 0) || (buf4[UDPCKSUML] != 0)) {
			fix_cksum(buf4 + UDPCKSUMH,
				  n->nsrc, n->src,
				  n->nport, n->sport);
		}
		break;
	case IPICMP:
		fix_cksum(buf4 + ICMPCKSUMH,
			  NULL, NULL,
			  n->nport, n->sport);
		break;
	}
	if (n->timeout && !increased &&
	    (seconds + (time_t) n->lifetime > n->timeout)) {
		n->timeout = seconds + n->lifetime;
		nat_heap_decreased(n->heap_index);
	}
	if (n != n->tunnel->tnat_root[pr])
		nat_splay_splay(pr, n);
	statsnatout++;
	if (n->tunnel->flags & TUNDEBUG)
		debugnatout++;
	return n->tunnel;
}

/* ICMP from Internet to tunnel */

struct tunnel *
naticmpout(void)
{
	struct nat *n, nat0;
	int cksum;
	u_char pr;

	logdebug(10, "naticmpout");

	nat0.proto = buf4[IP2PROTO];
	if (nat0.proto == IPTCP)
		pr = TCPPR;
	else
		pr = UDPPR;
	nat0.flags = MATCH_PORT;
	memcpy(nat0.nsrc, buf4 + IPDST, 4);
	memcpy(nat0.dst, buf4 + IP2DST, 4);
	memcpy(nat0.nport, buf4 + IP2SPORT, 2);
	memcpy(nat0.dport, buf4 + IP2DPORT, 2);
	n = nat_lookup(pr, &nat0);
	if (n == NULL) {
		logdebug(10, "no nat entry for naticmpout");
		statsdropped[DR_NATOUT]++;
		return NULL;
	}
	if ((buf4[IPOFFH] & IPDF) &&
	    (len + IP6HDRLEN > (u_int) n->tunnel->mtu)) {
		logdebug(10, "too large with DF (naticmpout)");
		statsdropped[DR_TOOBIG]++;
		if (n->tunnel->flags & TUNDEBUG)
			debugdropped[DR_TOOBIG]++;
		return NULL;
	}
	if (n->flags & PRR_NULL)
		goto prr_short_cut;
	memcpy(buf4 + IPDST, n->src, 4);
	fix_cksum(buf4 + IPCKSUMH, n->nsrc, n->src, NULL, NULL);
	memcpy(buf4 + IP2SRC, n->src, 4);
	memcpy(buf4 + IP2SPORT, n->sport, 2);
	fix_cksum(buf4 + IP2CKSUMH, n->nsrc, n->src, NULL, NULL);
	buf4[ICMPCKSUMH] = buf4[ICMPCKSUML] = 0;
	cksum = in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN);
	buf4[ICMPCKSUMH] = cksum >> 8;
	buf4[ICMPCKSUML] = cksum & 0xff;
	if (n->timeout && (seconds + nat_lifetime[3] > n->timeout)) {
		n->timeout = seconds + nat_lifetime[3];
		nat_heap_decreased(n->heap_index);
	}
    prr_short_cut:
	/* don't promote to head */
	statsnaticmpout++;
	if (n->tunnel->flags & TUNDEBUG)
		debugnaticmpout++;
	return n->tunnel;
}

/* NO-NAT from Internet to tunnel */

struct tunnel *
nonatout(void)
{
	struct tunnel *t = NULL;

	logdebug(10, "nonatout");

	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		const u_char *m = mask4[t->nnplen];

		if ((t->flags & TUNNONAT) == 0) {
			logerr("a not no-nat in no-nat list[%s]\n",
			       addr2str(AF_INET6, t->remote));
			continue;
		}
		if (((buf4[IPDST] & m[0]) == t->nnaddr[0]) &&
		    ((buf4[IPDST + 1] & m[1]) == t->nnaddr[1]) &&
		    ((buf4[IPDST + 2] & m[2]) == t->nnaddr[2]) &&
		    ((buf4[IPDST + 3] & m[3]) == t->nnaddr[3]))
			break;
	}
	if (t == NULL) {
		logerr("can't refind the no-nat entry for %s\n",
		       addr2str(AF_INET, buf4 + IPDST));
		return NULL;
	}

	if ((buf4[IPOFFH] & IPDF) &&
	    (buf4[IPPROTO] != IPICMP) &&
	    ((buf4[IPOFFH] & IPOFFMSK) == 0) &&
	    (buf4[IPOFFL] == 0) &&
	    (len + IP6HDRLEN > (u_int) t->mtu) &&
	    (t->flags & TUNTBDROP)) {
		logdebug(10, "too big dropped");
		statsdropped[DR_TOOBIG]++;
		if (t->flags & TUNDEBUG)
			debugdropped[DR_TOOBIG]++;
		return NULL;
	}
	if (buf4[IPPROTO] == IPTCP)
		patch_tcpmss(t);
	statsnonatout++;
	if (t->flags & TUNDEBUG)
		debugnonatout++;
	return t;
}

/* Filter ICMPv4 packets from Internet
 * Returns 1 if packet is okay to send, 0 otherwise
 */

int
filtericmpout(void)
{
	u_int l, i;

	logdebug(10, "filtericmpout");

	/* sanity checks */
	if (len < IP2 + IPMINLEN) {
		logerr("short(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	switch (buf4[ICMPTYPE]) {
	case 3:		/* unreachable */
	case 11:	/* time exceeded */
	case 12:	/* parameter problem */
		break;
	default:
		logdebug(10, "unhandled icmp type %d", (int)buf4[ICMPTYPE]);
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}

	/* sanity checks on referenced IPv4 header */
	if (buf4[IP2] != IP4VNOOP) {
		logerr("byte0(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if ((buf4[IP2SRC] == 127) || (buf4[IP2DST] == 127)) {
		logerr("localnet(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if ((buf4[IP2SRC] >= 224) || (buf4[IP2DST] >= 224)) {
		logerr("multicast(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if ((buf4[IP2PROTO] != IPTCP) && (buf4[IP2PROTO] != IPUDP)) {
		logerr("protocol(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if (memcmp(buf4 + IPDST, buf4 + IP2SRC, 4) != 0) {
		logerr("destination(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	l = buf4[IP2LENH] << 8;
	l |= buf4[IP2LENL];
	if (l < IPMINLEN) {
		logerr("short(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if (in_cksum(buf4 + IP2, IPHDRLEN) != 0) {
		logerr("checksum(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	if ((buf4[IP2OFFH] & IPOFFMSK) || (buf4[IP2OFFL] != 0)) {
		logerr("fragment(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	/* naticmpout() will recompute it from scratch */
	if (in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN) != 0) {
		logerr("checksum2(filtericmpout)\n");
		statsdropped[DR_ICMPOUT]++;
		return 0;
	}
	for (i = 0; i < poolcnt; i++) {
		if (memcmp(buf4 + IPDST, pools[i]->addr, 4) == 0)
			return 1;
	}
	statsdropped[DR_DSTOUT]++;
	return 0;
}

/* Filter IPv4 packets from Internet
 * Returns:
 * 0: drop packet
 * 1: perform inbound nat on packet
 * 2: perform inbound nat on icmp packet 
 * 3: perform inbound no-nat on packet
 */

int
filterout(void)
{
	struct tunnel *t;
	u_int l, i;
#ifdef notyet
	u_char tlen[2];
#endif
	char src[16], dst[16];
	int ret = -1;

    again:
	logdebug(10, "filterout");

	/* sanity checking */
	if (len < IPMINLEN) {
		logerr("length(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	if (buf4[0] != IP4VNOOP) {
		logerr("byte0(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	if ((buf4[IPSRC] == 127) || (buf4[IPDST] == 127)) {
		logerr("localnet(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	if ((buf4[IPSRC] >= 224) || (buf4[IPDST] >= 224)) {
		logerr("multicast(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	l = buf4[IPLENH] << 8;
	l |= buf4[IPLENL];
	if ((l < IPMINLEN) || (l > len)) {
		logerr("short(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	len = l;
	if (in_cksum(buf4, IPHDRLEN) != 0) {
		logerr("checksum(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}

	/* shortcut destination address control if already done */
	if (ret >= 0)
		goto done;

	/* no-nat matching is here */
	ISC_STAILQ_FOREACH(t, &nonats, nchain) {
		const u_char *m = mask4[t->nnplen];

#ifdef notyet
		/* both expensive and what to do?! */
		if ((t->flags & TUNNONAT) == 0) {
			logerr("a not no-nat in no-nat list\n");
			continue;
		}
#endif
		if (((buf4[IPDST] & m[0]) == t->nnaddr[0]) &&
		    ((buf4[IPDST + 1] & m[1]) == t->nnaddr[1]) &&
		    ((buf4[IPDST + 2] & m[2]) == t->nnaddr[2]) &&
		    ((buf4[IPDST + 3] & m[3]) == t->nnaddr[3])) {
			ret = 3;
			goto done;
		}
	}

	/* match dst to a public NAT addr */
	for (i = 0; i < poolcnt; i++) {
		if (memcmp(buf4 + IPDST, pools[i]->addr, 4) == 0) {
			ret = 0;
			goto done;
		}
	}
	logerr("dest(filterout): no nat binding for %s from %s\n", 
	       inet_ntop(AF_INET, buf4 + IPDST, dst, 16),
	       inet_ntop(AF_INET, buf4 + IPSRC, src, 16));
	statsdropped[DR_DSTOUT]++;
	return 0;

    done:
	if ((buf4[IPPROTO] != IPTCP) &&
	    (buf4[IPPROTO] != IPUDP) &&
	    (buf4[IPPROTO] != IPICMP)) {
		logerr("proto(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
	if ((buf4[IPOFFH] & (IPMF|IPOFFMSK)) || (buf4[IPOFFL] != 0)) {
		/* IPv4 fragment, try to reassemble */
		if (defrag(NULL))
			/* if packet can be successfully reassembled,
			 * process it as a new packet
			 */
			goto again;
		return 0;
	}
	switch (buf4[IPPROTO]) {
	case IPTCP:
		if (len < IPHDRLEN + 20) {
			logerr("short(TCP, filterout)\n");
			statsdropped[DR_BADOUT]++;
			return 0;
		}
		if (ret != 3)
			ret = 1;
		break;

	case IPUDP:
		if (ret != 3)
			ret = 1;
		break;

	case IPICMP:
		if (ret == 3)
			break;
		if (buf4[ICMPTYPE] == ICMPECHREP)
			/* ping reply doesn't include referenced IPv4 header,
			 * so don't do the extra validation of filtericmpout
			 */
			ret = 1;
		else if (filtericmpout())
			ret = 2;
		break;

	default:
		logerr("proto(filterout)\n");
		statsdropped[DR_BADOUT]++;
		return 0;
	}
#ifdef notyet
	switch (buf4[IPPROTO]) {
	case IPTCP:
		tlen[0] = (len - IPHDRLEN) >> 8;
		tlen[1] = (len - IPHDRLEN) & 0xff;
		if (pseudo_cksum(buf4, tlen, len) != 0) {
			logerr("checksum(TCP, filterout)\n");
			statsdropped[DR_BADOUT]++;
			return 0;
		}
		break;

	case IPUDP:
		if (((buf4[UDPCKSUMH] != 0) || (buf4[UDPCKSUML] != 0)) &&
		    (pseudo_cksum(buf4, buf4 + UDPLEN, len) != 0)) {
			logerr("checksum(UDP, filterout)\n");
			statsdropped[DR_BADOUT]++;
			return 0;
		}
		break;

	case IPICMP:
		if (in_cksum(buf4 + IPHDRLEN, len - IPHDRLEN) != 0) {
			logerr("checksum(ICMP, filterout)\n");
			statsdropped[DR_BADOUT]++;
			return 0;
		}
		break;
	}
#endif
	return ret;
}

/* Encapsulate IPv4 packets into IPv6, and send the packet */

void
encap(struct tunnel *t)
{
	u_int off, flen, mtu;
	u_int fmtu, nfrag, flen0, fleno;
	uint32_t id;
	int cc, fcc;
#ifdef notyet
	u_char tos;
#endif

	logdebug(10, "encap: tunnel %s", addr2str(AF_INET6, t->remote));

	mtu = (u_int) t->mtu;
	if (len + IP6HDRLEN <= mtu) {
		/* simple case: packet fits in the tunnel mtu */
		memset(buf6, 0, IP6HDRLEN);
		buf6[0] = IP6V;
#ifdef notyet
		tos = buf4[IPTOS];
		if ((tos & 3) == 3)
			tos &= ~0x02;		/* CE -> ECT(0) */
		buf6[0] |= tos >> 4;
		buf6[1] = tos << 4;
#endif
		buf6[IP6LENH] = len >> 8;
		buf6[IP6LENL] = len & 0xff;
		buf6[IP6PROTO] = IP6IP4;
		buf6[IP6TTL] = 64;		/* default TTL */
		memcpy(buf6 + IP6SRC, local6, 16);
		memcpy(buf6 + IP6DST, t->remote, 16);
		memcpy(buf6 + IP6HDRLEN, buf4, len);
		len += IP6HDRLEN;

		cc = tun_write(AF_INET6, buf6, len);
		if (cc < 0)
			logcrit("write(encap): %s\n", strerror(errno));
		else if (cc != (int) len)
			logcrit("short(encap)\n");
		else {
			statssent6++;
			if (t->flags & TUNDEBUG)
				debugsent6++;
		}
		return;
	}

	/* fragment the packet */
	logdebug(10, "encap: len %u > mtu % u, fragmenting",
		 len + IP6HDRLEN, mtu);
	memset(buf6, 0, IP6FLEN);
	buf6[0] = IP6V;
#ifdef notyet
	tos = buf4[IPTOS];
	if ((tos & 3) == 3)
		tos &= ~0x02;		/* CE -> ECT(0) */
	buf6[0] |= tos >> 4;
	buf6[1] = tos << 4;
#endif
	buf6[IP6PROTO] = IP6FRAG;
	buf6[IP6TTL] = 64;		/* default TTL */
	memcpy(buf6 + IP6SRC, local6, 16);
	memcpy(buf6 + IP6DST, t->remote, 16);
	buf6[IP6FPROTO] = IP6IP4;
	id = arc4_getword();
	memcpy(buf6 + IP6FID, &id, 4);

	flen0 = 0;		/* XXX: silence compiler */
	fleno = 0;
	if (eqfrag) {
		fmtu = (mtu - IP6FLEN) & ~7;
		nfrag = len / fmtu;			/* always >= 1 */
		if (len % fmtu != 0)
			nfrag++;
		/* len = fmtu * (nfrag - 1) + rem; 0 <= rem < fmtu */
		fleno = (len / nfrag) & ~7;		/* lower medium size */
		flen0 = len - fleno * (nfrag - 1);	/* remainder */
		flen0 = (flen0 + 7) & ~7;
		if (flen0 > fmtu) {
			/* too much remainder, switch to bigger medium size,
			   but still <= fmtu */
			fleno += 8;
			/* recompute remainder (shall be this time <= fmtu) */
			flen0 = len - (fleno * (nfrag - 1));
			flen0 = (flen0 + 7) & ~7;
		}
		/* biggest should be first, smallest last */
		if (flen0 < fleno)
			flen0 = fleno;
	}
	for (off = 0; off < len; off += flen) {
		flen = len - off;
		if (flen > mtu - IP6FLEN) {
			if (eqfrag) {
				if (off == 0) /* first fragment */
					flen = flen0;
				else /* intermediate fragment */
					flen = fleno;
			} else {
				flen = mtu - IP6FLEN;
				flen &= ~7;
			}
		}
		buf6[IP6FOFFH] = off >> 8;
		buf6[IP6FOFFL] = off & IP6FMSK;
		if (flen + off < len)
			buf6[IP6FOFFL] |= IP6FMF;
		buf6[IP6LENH] = (flen + 8) >> 8;
		buf6[IP6LENL] = (flen + 8) & 0xff;
		memcpy(buf6 + IP6FLEN, buf4 + off, flen);
		fcc = (int) flen + IP6FLEN;

		cc = tun_write(AF_INET6, buf6, fcc);
		if (cc < 0) {
			logcrit("write(encap): %s\n", strerror(errno));
			return;
		} else if (cc != fcc) {
			logcrit("short(encap)\n");
			return;
		}
		statsfrgout6++;
		if (t->flags & TUNDEBUG)
			debugfrgout6++;
	}
	statssent6++;		
	if (t->flags & TUNDEBUG)
		debugsent6++;
}

/*
 * Main...
 */

/* Fork child loop */

void
fork_child(struct sess *ss0)
{
	struct sess *ss;
	int ret;

	if (tunfd >= 0)
		(void) close(tunfd);
	tunfd = -1;
	if (reload_stream != NULL)
		(void) fclose(reload_stream);
	reload_stream = NULL;
	ISC_LIST_FOREACH(ss, &sslist, chain) {
		if (ss == ss0)
			continue;
		if (ss->sserr != NULL)
			(void) fclose(ss->sserr);
		ss->sserr = NULL;
		if (ss->ssnot != NULL)
			(void) fclose(ss->ssnot);
		ss->ssnot = NULL;
		if (ss->ssout != NULL)
			(void) close(fileno(ss->ssout));
		if (ss->fd >= 0)
			(void) close(ss->fd);
		ss->fd = -1;
	}
	if (tcp4_fd != -1)
		(void) close(tcp4_fd);
	tcp4_fd = -1;
	if (tcp6_fd != -1)
		(void) close(tcp6_fd);
	tcp6_fd = -1;
	if (unix_fd != -1)
		(void) close(unix_fd);
	unix_fd = -1;
	closelog();
	openlog("aftr", AFTRLOGOPTION, AFTRFACILITY);

	logdebug(0, "forked child (pid=%u)", (u_int) getpid());

	for (;;) {
		if (ss0->fd == -1)
			break;
		ret = commands(ss0);
		if (ret == 2)
			sslogerr(ss0, "forked child: no reboot\n");
		else if (ret == 1)
			break;
	}
	logdebug(0, "forked child: done\n");
	exit(0);
}

/* Incremental GC */

void
gc_incr(void)
{
	struct sess *ss, *tss;
	struct nat *n, *tn;
	int remains = (int) quantum;

	logdebug(10, "gc_incr");

	ISC_LIST_FOREACH_SAFE(ss, &orphans, chain, tss) {
		ISC_LIST_FOREACH_SAFE(n, &ss->snats, gchain, tn) {
			ISC_LIST_REMOVE(n, gchain);
			del_nat(n);
			if (--remains == 0)
				return;
		}
		ISC_LIST_REMOVE(ss, chain);
		if (ss == reload_session) {
			logcrit("GC reload session?\n");
			exit(-1);
		}
		if ((ss->locked & 2) == 0) {
			if (ss->name)
				free(ss->name);
			ISC_MAGIC_FREE(ss, ISC_SESSION_MAGIC);
			free(ss);
		}
	}

	if (needgc > 1) {
		if (gc_ptr == NULL)
			gc_ptr = ISC_LIST_FIRST(&confnats);
		needgc = 1;
	}
	for (n = gc_ptr; n != NULL; n = gc_ptr) {
		gc_ptr = ISC_LIST_NEXT(n, gchain);
		if ((n->generation < FIRSTGEN) || (n->generation >= lastgen))
			continue;
		ISC_LIST_REMOVE(n, gchain);
		del_nat(n);
		if (--remains == 0)
			return;
	}
	logdebug(0, "garbage collection done");
	needgc = 0;
}

/* Incremental backtrack */

void
bt_incr(void)
{
	struct nat *n;
	int remains = 5 * (int) quantum;

	logdebug(10, "bt_incr");

	if (needbt > 1) {
		if (bt_ptr == NULL)
			bt_ptr = ISC_LIST_FIRST(&confnats);
		needbt = 1;
	}
	for (n = bt_ptr; n != NULL; n = bt_ptr) {
		bt_ptr = ISC_LIST_NEXT(n, gchain);
		if (n->generation > lastgen)
			n->generation = lastgen;
		if (--remains == 0)
			return;
	}
	logdebug(0, "reload backtrack done");
	needbt = 0;
}

/* One packet */

int
loop1(void)
{
	struct tunnel *t;
	int cc;

	cc = tun_read(buf, sizeof(buf));
	if (cc < 0) {
		if (cc != -EWOULDBLOCK)
			logcrit("read: %s\n", strerror(errno));
		return -1;
	}
	if (cc == 0) {
		logcrit("read zero bytes\n");
		return -1;
	}

	/* IPv6 packet: probably tunneled IPv4 from AFTR client */
	if ((buf[0] & IPVERMSK) == IP6V) {
		statsrcv6++;
		len = cc;
		if (len < IP6HDRLEN + 8 + 8) {
			logerr("short IPv6 packet\n");
			statsdropped[DR_BAD6]++;
			return 0;
		}
		memcpy(buf6, buf, len);
		t = decap();
		if (t == NULL)
			return 0;
		if (t->flags & TUNDEBUG)
			debugrcv6++;
		switch (filterin(t)) {
		case 1:
			if (natin(t))
				break;
			else
				return 0;
		case 2:
			if (prrin(t))
				break;
			else
				return 0;
		case 3:
			if (nonatin(t))
				break;
			else
				return 0;
		default:
			return 0;
		}
		/* IPv4 packet has been validated, rewritten
		 * in the NAT case; now send it
		 */
		cc = tun_write(AF_INET, buf4, len);
		if (cc < 0) {
			logcrit("write: %s\n", strerror(errno));
			return -1;
		} else if (cc != (int) len) {
			logerr("write returned %d, expected %d\n", cc, len);
			return -1;
		} else {
			logdebug(3, "wrote %d bytes", cc);
			statssent4++;
			if (t->flags & TUNDEBUG)
				debugsent4++;
		}
		return 0;
	}

	/* IPv4 packet: probably NATed packet for AFTR client */
	if ((buf[0] & IPVERMSK) == IP4V) {
		statsrcv4++;
		len = cc;
		if (len < IPMINLEN) {
			logerr("short IPv4 packet\n");
			statsdropped[DR_BADOUT]++;
			return 0;
		}
		memcpy(buf4, buf, len);
		switch (filterout()) {
		case 1:
			t = natout();
			if (t == NULL)
				return 0;
			if (t->flags & TUNDEBUG)
				debugrcv4++;
			encap(t);
			break;

		case 2:
			t = naticmpout();
			if (t == NULL)
				return 0;
			if (t->flags & TUNDEBUG)
				debugrcv4++;
			encap(t);
			break;

		case 3:
			t = nonatout();
			if (t == NULL)
				return 0;
			if (t->flags & TUNDEBUG)
				debugrcv4++;
			encap(t);
			break;

		default:
			return 0;
		}
		return 0;
	}
	logerr("unexpected IP version number %d\n", (buf[0] & IPVERMSK) >> 4);
	return 0;
}

/* Main loop */

int
loop(void)
{
	struct sess *ss, *tss;
	struct nat *n;
	struct frag *f;
	fd_set set;
	struct timeval tv;
	int maxfd, cc, cnt;
	double delta;

	FD_ZERO(&set);
	FD_SET(tunfd, &set);
	maxfd = tunfd;
	if (reloading)
		reload_incr();
	if (!reloading) {
		ISC_LIST_FOREACH(ss, &sslist, chain)
			if (ss->fd != -1) {
				FD_SET(ss->fd, &set);
				if (ss->fd > maxfd)
					maxfd = ss->fd;
			}
	}
	if (unix_fd != -1) {
		FD_SET(unix_fd, &set);
		if (unix_fd > maxfd)
			maxfd = unix_fd;
	}
	if (tcp4_fd != -1) {
		FD_SET(tcp4_fd, &set);
		if (tcp4_fd > maxfd)
			maxfd = tcp4_fd;
	}
	if (tcp6_fd != -1) {
		FD_SET(tcp6_fd, &set);
		if (tcp6_fd > maxfd)
			maxfd = tcp6_fd;
	}
	if (reloading || needgc || needbt) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
	} else {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
	}

	cc = select(maxfd + 1, &set, NULL, NULL, &tv);
	if (cc < 0) {
		if (errno != EINTR) {
			logcrit("select: %s\n", strerror(errno));
			exit(-1);
		}
		return 0;
	}
	seconds = time(NULL);

	/* new control channel session */
	if ((unix_fd != -1) && FD_ISSET(unix_fd, &set))
		(void) unix_open();
	if ((tcp4_fd != -1) && FD_ISSET(tcp4_fd, &set))
		(void) tcp4_open();
	if ((tcp6_fd != -1) && FD_ISSET(tcp6_fd, &set))
		(void) tcp6_open();

	/* deal with interactive commands */
	if (!reloading) {
		ISC_LIST_FOREACH_SAFE(ss, &sslist, chain, tss)
			if ((ss->fd != -1) &&
			    ((ss->cpos != 0) || FD_ISSET(ss->fd, &set))) {
				cc = commands(ss);
				if (cc > 0)
					return cc;
			}
	}

	/* deal with packets on the tunnel interface */
	if (FD_ISSET(tunfd, &set)) {
		cnt = (int) quantum;
		do {
			if (loop1() != 0)
				break;
		} while (--cnt > 0);
	}

	/* incremental activities */
	if (needgc)
		gc_incr();
	if (needbt)
		bt_incr();

	/* every second: decay rates, expire nats, fragments */
	if (seconds != lastsecs) {
		while (seconds > lastsecs) {
			ratercv6[0] *= decays[0];
			ratercv6[1] *= decays[1];
			ratercv6[2] *= decays[2];
			ratercv4[0] *= decays[0];
			ratercv4[1] *= decays[1];
			ratercv4[2] *= decays[2];
			ratesent6[0] *= decays[0];
			ratesent6[1] *= decays[1];
			ratesent6[2] *= decays[2];
			ratesent4[0] *= decays[0];
			ratesent4[1] *= decays[1];
			ratesent4[2] *= decays[2];
			ratecnat[0] *= decays[0];
			ratecnat[1] *= decays[1];
			ratecnat[2] *= decays[2];
			ratednat[0] *= decays[0];
			ratednat[1] *= decays[1];
			ratednat[2] *= decays[2];
			lastsecs++;
		}
		delta = (double) (statsrcv6 - lastrcv6);
		lastrcv6 = statsrcv6;
		ratercv6[0] += (1.0 - decays[0]) * delta;
		ratercv6[1] += (1.0 - decays[1]) * delta;
		ratercv6[2] += (1.0 - decays[2]) *delta;
		delta = (double) (statsrcv4 - lastrcv4);
		lastrcv4 = statsrcv4;
		ratercv4[0] += (1.0 - decays[0]) * delta;
		ratercv4[1] += (1.0 - decays[1]) * delta;
		ratercv4[2] += (1.0 - decays[2]) * delta;
		delta = (double) (statssent6 - lastsent6);
		lastsent6 = statssent6;
		ratesent6[0] += (1.0 - decays[0]) * delta;
		ratesent6[1] += (1.0 - decays[1]) * delta;
		ratesent6[2] += (1.0 - decays[2]) * delta;
		delta = (double) (statssent4 - lastsent4);
		lastsent4 = statssent4;
		ratesent4[0] += (1.0 - decays[0]) * delta;
		ratesent4[1] += (1.0 - decays[1]) * delta;
		ratesent4[2] += (1.0 - decays[2]) * delta;
		delta = (double) (statscnat - lastcnat);
		lastcnat = statscnat;
		ratecnat[0] += (1.0 - decays[0]) * delta;
		ratecnat[1] += (1.0 - decays[1]) * delta;
		ratecnat[2] += (1.0 - decays[2]) * delta;
		delta = (double) (statsdnat - lastdnat);
		lastdnat = statsdnat;
		ratednat[0] += (1.0 - decays[0]) * delta;
		ratednat[1] += (1.0 - DECAY5) * delta;
		ratednat[2] += (1.0 - decays[2]) * delta;

		free_heldnats();
		for (;;) {
			n = nat_heap_element(1);
			if ((n == NULL) || (n->timeout >= seconds))
				break;
			del_nat(n);
		}
		for (;;) {
			f = ISC_TAILQ_LAST(&frags6, fragshead);
			if ((f == NULL) || (f->expire >= seconds))
				break;
			statsdropped[DR_F6TM]++;
			if (f->tunnel->flags & TUNDEBUG)
				debugdropped[DR_F6TM]++;
			del_frag6(f);
		}
		for (;;) {
			f = ISC_TAILQ_LAST(&fragsin, fragshead);
			if ((f == NULL) || (f->expire >= seconds))
				break;
			statsdropped[DR_FINTM]++;
			if (f->tunnel->flags & TUNDEBUG)
				debugdropped[DR_FINTM]++;
			del_frag4(f);
		}
		for (;;) {
			f = ISC_TAILQ_LAST(&fragsout, fragshead);
			if ((f == NULL) || (f->expire >= seconds))
				break;
			statsdropped[DR_FOUTTM]++;
			del_frag4(f);
		}
		lastsecs = seconds;
	}

	/* every 256 seconds: resize hash tables */
	if (((seconds - startsecs) & 0xff) == 0) {
		arc4_stir();
		if (pfhlookups / 4 > pfhhits) {
			u_int newhashsz;
			struct frag **newhash;

			newhashsz = fraghashsz * 2;
			if (newhashsz > MAXFRAGHASH) {
				logerr("fragment trashing\n");
				goto natsz;
			}
			newhash = (struct frag **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newfraghash): %s\n",
				       strerror(errno));
				goto natsz;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			fraghashsz = newhashsz;
			free(fraghash);
			fraghash = newhash;
			fraghashrnd = arc4_getword();
			pfhhits = newhashsz;
			loginfo("upsize fragment hash\n");
		} else if ((9 * pfhlookups) / 10 < pfhhits) {
			u_int newhashsz;
			struct frag **newhash;

			newhashsz = fraghashsz / 2;
			if (newhashsz < MINFRAGHASH)
				goto natsz;
			newhash = (struct frag **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newfraghash): %s\n",
				       strerror(errno));
				goto natsz;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			fraghashsz = newhashsz;
			free(fraghash);
			fraghash = newhash;
			fraghashrnd = arc4_getword();
			pfhhits = newhashsz;
			loginfo("downsize fragment hash\n");
		}
	    natsz:
		if (pnhlookups / 4 > pnhhits) {
			u_int newhashsz;
			struct nat **newhash;

			newhashsz = nathashsz * 2;
			if (newhashsz > MAXNATHASH) {
				logerr("NAT trashing\n");
				goto tunsz;
			}
			newhash = (struct nat **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newnathash): %s\n",
				       strerror(errno));
				goto tunsz;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			nathashsz = newhashsz;
			free(nathash);
			nathash = newhash;
			nathashrnd = arc4_getword();
			pnhhits = newhashsz;
			loginfo("upsize NAT hash\n");
		} else if ((9 * pnhlookups) / 10 < pnhhits) {
			u_int newhashsz;
			struct nat **newhash;

			newhashsz = nathashsz / 2;
			if (newhashsz < MINNATHASH)
				goto tunsz;
			newhash = (struct nat **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newnathash): %s\n",
				       strerror(errno));
				goto tunsz;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			nathashsz = newhashsz;
			free(nathash);
			nathash = newhash;
			nathashrnd = arc4_getword();
			pnhhits = newhashsz;
			loginfo("downsize NAT hash\n");
		}
	    tunsz:
		if (pthlookups / 4 > pthhits) {
			u_int newhashsz;
			struct tunnel **newhash;

			newhashsz = tunhashsz * 2;
			if (newhashsz > MAXTUNHASH) {
				logerr("tunnel trashing\n");
				return 0;
			}
			newhash = (struct tunnel **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newtunhash): %s\n",
				       strerror(errno));
				return 0;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			tunhashsz = newhashsz;
			free(tunhash);
			tunhash = newhash;
			tunhashrnd = arc4_getword();
			pthhits = newhashsz;
			loginfo("upsize tunnel hash\n");
		} else if ((9 * pthlookups) / 10 < pthhits) {
			u_int newhashsz;
			struct tunnel **newhash;

			newhashsz = tunhashsz / 2;
			if (newhashsz < MINTUNHASH)
				return 0;
			newhash = (struct tunnel **)
				malloc(newhashsz * sizeof(*newhash));
			if (newhash == NULL) {
				logerr("malloc(newtunhash): %s\n",
				       strerror(errno));
				return 0;
			}
			memset(newhash, 0, newhashsz * sizeof(*newhash));
			tunhashsz = newhashsz;
			free(tunhash);
			tunhash = newhash;
			tunhashrnd = arc4_getword();
			pthhits = newhashsz;
			loginfo("downsize tunnel hash\n");
		}
	}
	return 0;
}

/* Initialize hash tables */

void
init_hashes(void)
{
	lastsecs = startsecs = time(NULL);

	fraghashsz = MINFRAGHASH;
	fraghashrnd = (uint32_t) arc4_getword();
	fraghash = (struct frag **) malloc(fraghashsz * sizeof(*fraghash));
	if (fraghash == NULL) {
		logcrit("malloc(fraghash): %s\n", strerror(errno));
		exit(-1);
	}
	memset(fraghash, 0, fraghashsz * sizeof(*fraghash));
	pfhhits = fraghashsz;

	nathashsz = MINNATHASH;
	nathashrnd = (uint32_t) arc4_getword();
	nathash = (struct nat **) malloc(nathashsz * sizeof(*nathash));
	if (nathash == NULL) {
		logcrit("malloc(nathash): %s\n", strerror(errno));
		exit(-1);
	}
	memset(nathash, 0, nathashsz * sizeof(*nathash));

	tunhashsz = MINTUNHASH;
	tunhashrnd = (uint32_t) arc4_getword();
	tunhash = (struct tunnel **) malloc(tunhashsz * sizeof(*tunhash));
	if (tunhash == NULL) {
		logcrit("malloc(tunhash): %s\n", strerror(errno));
		exit(-1);
	}
	memset(tunhash, 0, tunhashsz * sizeof(*tunhash));
}

/* Run setup start script */

void
setup_start(void)
{
	int len, fd;

	len = strlen(aftrscript) + strlen("start") + 2;
	setup_cmd = (char *) malloc(len);
	if (setup_cmd == NULL) {
		logcrit("malloc(start): %s\n", strerror(errno));
		exit(-1);
	}
	memset(setup_cmd, 0, len);
	sprintf(setup_cmd, "%s start", aftrscript);
	fd = tun_open();
	if (fd <= 0) {
		logcrit("tun_open() failed\n");
		exit(-1);
	}
	if (system(setup_cmd) != 0) {
		logcrit("system() failed\n");
		(void) close(fd);
		exit(-1);
	}
	tunfd = fd;
}

/* Run setup stop script */

void
setup_stop(void)
{
	sprintf(setup_cmd, "%s stop", aftrscript);
#if defined(__GNUC__) && (__GNUC__ > 3)
	__builtin_expect(system(setup_cmd), 0);
#else
	(void) system(setup_cmd);
#endif
	(void) close(tunfd);
	tunfd = -1;
}

/* Reap children */

void
reapchild(int sig)
{
	int status;

	sig = sig;
	while (wait3(&status, WNOHANG, NULL) > 0)
		/* continue */;
}

/* Sanity and final initial conf checks */

int
conf_global_check(void)
{
	int ret = 0;

	/* these have to be checked at startup, because the preprocessor
	 * can't do floating point comparisons
	 */
	if ((DECAY1 < 0.0) || (DECAY1 > 1.0)) {
		logcrit("bad DECAY1 %f\n", DECAY1);
		ret = -1;
	}
	if ((DECAY5 < 0.0) || (DECAY5 > 1.0)) {
		logcrit("bad DECAY5 %f\n", DECAY5);
		ret = -1;
	}
	if ((DECAY15 < 0.0) || (DECAY15 > 1.0)) {
		logcrit("bad DECAY15 %f\n", DECAY15);
		ret = -1;
	}
	return ret;
}

int
init_acl4(void)
{
	struct acl4 *a;
	int i;

	for (i = 0; i < 4; i++) {
		a = (struct acl4 *) malloc(sizeof(*a));
		if (a == NULL) {
			logcrit("malloc(acl4): %s\n", strerror(errno));
			return -1;
		}
		memset(a, 0, sizeof(*a));
		ISC_MAGIC_SET(a, ISC_ACL4_MAGIC);
		switch (i) {
		case 0:
			a->addr[0] = 10;
			memcpy(a->mask, mask4[8], 4);
			break;
		case 1:
			a->addr[0] = 172;
			a->addr[1] = 16;
			memcpy(a->mask, mask4[12], 4);
			break;
		case 2:
			a->addr[0] = 192;
			a->addr[1] = 168;
			memcpy(a->mask, mask4[16], 4);
			break;
		default:
			a->addr[0] = 192;
			memcpy(a->mask, mask4[29], 4);
		}
		ISC_STAILQ_INSERT_TAIL(&acl4s, a, chain);
	}
	return 0;
}

int
conf_required_check(void)
{
	if (!local6_set) {
		logcrit("missing \"address endpoint\"\n");
		return -1;
	}
	if (!icmpsrc_set) {
		logcrit("missing \"address icmp\"\n");
		return -1;
	}
	if (poolcnt == 0) {
		logcrit("missing \"pool\"\n");
		return -1;
	}
	if (ISC_STAILQ_EMPTY(&acl6s)) {
		logcrit("missing \"acl6\"\n");
		return -1;
	}
	if (ISC_STAILQ_EMPTY(&acl4s)) {
		logcrit("removed all \"private\"\n");
		return -1;
	}
	return 0;
}

/* main */

int
main(int argc, char *argv[])
{
	int i, ret = 0, opt, daemonize = 1;
	char *progname, *saved_argv[20], *sunname = NULL;
	struct sess *ss1;
	extern char *optarg;
	extern int optind;

	ISC_TAILQ_INIT(&frags6);
	ISC_TAILQ_INIT(&fragsin);
	ISC_TAILQ_INIT(&fragsout);
	ISC_STAILQ_INIT(&nonats);
	ISC_STAILQ_INIT(&acl6s);
	ISC_STAILQ_INIT(&acl4s);

	progname = argv[0];
	if (argc >= 20) {
		fprintf(stderr, "%s: too many arguments\n", progname);
		return -1;
	}
	for (i = 0; i < 20; i++) {
		if (i < argc)
			saved_argv[i] = argv[i];
		else
			saved_argv[i] = NULL;
	}

	aftrconfig = getenv("AFTRCONFIG");
	if (aftrconfig != NULL)
		aftrconfig = strdup(aftrconfig);
	aftrscript = getenv("AFTRSCRIPT");
	if (aftrscript != NULL)
		aftrscript = strdup(aftrscript);
	aftrdevice = getenv("AFTRDEVICE");
	if (aftrdevice != NULL)
		aftrdevice = strdup(aftrdevice);

	while ((opt = getopt(argc, argv, "gc:s:d:p:u:t")) != -1)
		switch (opt) {
		case 'c':
			if (aftrconfig != NULL)
				free(aftrconfig);
			aftrconfig = optarg;
			break;
		case 'd':
			if (aftrdevice != NULL)
				free(aftrdevice);
			aftrdevice = optarg;
			break;
		case 'g':
			daemonize = 0;
			break;
		case 'p':
			aftrport = atoi(optarg);
			if (aftrport == 0) {
				fprintf(stderr, "bad port %s\n", optarg);
				return -1;
			}
			break;
		case 's':
			if (aftrscript != NULL)
				free(aftrscript);
			aftrscript = optarg;
			break;
		case 'u':
			sunname = optarg;
			break;
		case 't':
			checkconf = 1;
			break;
		default:
		usage:
#define USAGE	\
"Usage: %s [-t] [-g] [-c config] [-s script] [-d device] [-p port|-u socket]\n"
			fprintf(stderr, USAGE, argv[0]);
			return -1;
		}
	if (optind != argc) {
		fprintf(stderr, "%s: extra arguments\n", argv[0]);
		goto usage;
	}

	if (aftrconfig == NULL)
		aftrconfig = AFTRCONFIG;
	if (aftrscript == NULL)
		aftrscript = AFTRSCRIPT;
	if (aftrdevice == NULL)
		aftrdevice = AFTRDEVICE;
#ifdef SIZES
	/* amd64: 56, 144, 64
	   i386:  40,  88, 36
	*/

	printf("tunnel=%d, nat=%d, frag=%d\n",
	       (int) sizeof(struct tunnel),
	       (int) sizeof(struct nat),
	       (int) sizeof(struct frag));
	if (offsetof(struct held, flags) != offsetof(struct nat, flags))
		printf("%d <> %d\n",
		       (int) offsetof(struct held, flags),
		       (int) offsetof(struct nat, flags));
#endif

	ss1 = stdio_open();
	seconds = time(NULL);
	openlog("aftr", AFTRLOGOPTION, AFTRFACILITY);
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGCHLD, reapchild);
	arc4_init();
	arc4_stir();
	init_hashes();
	lastgen++;
	curgen = lastgen;
	ss1->section = 1;
	ret = conf_global_check();
	if (ret != 0)
		return ret;
	ret = init_acl4();
	if (ret != 0)
		return ret;
	ret = load_conf(ss1);
	if (ret != 0)
		return ret;
	ret = conf_required_check();
	curgen = 0;
	if (ret != 0)
		return ret;
	if (checkconf)
		goto stop;
	setup_start();
	if (sunname != NULL)
		unix_start(sunname);
	else {
		tcp4_start();
		tcp6_start();
	}
	if (daemonize) {
		(void) close(ss1->fd);
		stdio_close(ss1);
		ret = daemon(1, 0);
		if (ret != 0) {
			logcrit("daemonize failed: %s\n", strerror(errno));
			return ret;
		}
	} else
		ss1->section = 8;
	while ((ret = loop()) == 0)
		/* continue */;
	setup_stop();
	sess_closeall(sunname);
  stop:
	closelog();
	if (ret == 2)
		(void) execv(progname, saved_argv);
	return 0;
}
