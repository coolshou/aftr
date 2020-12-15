# from  Makefile.linux,v 1.51 2010/03/09 09:53:00 nanard Exp $
# MiniUPnP project
# http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
# Author : Thomas Bernard
# for use with GNU Make
#
# To install use :
# $ PREFIX=/dummyinstalldir make -f Makefile.linux install
# or :
# $ INSTALLPREFIX=/usr/local make -f Makefile.linux install
# or :
# $ make -f Makefile.linux install
#
#
CFLAGS = -Wall -O -D_GNU_SOURCE -g -DDEBUG
#CFLAGS = -Wall -Os -D_GNU_SOURCE
CC = gcc
RM = rm -f
INSTALL = install
STRIP = strip

INSTALLPREFIX ?= $(PREFIX)/usr
SBININSTALLDIR = $(INSTALLPREFIX)/sbin
ETCINSTALLDIR = $(PREFIX)/etc/miniupnpd

BASEOBJS = miniupnpd.o upnphttp.o upnpdescgen.o upnpsoap.o \
           upnpreplyparse.o minixml.o \
	   upnpredirect.o getifaddr.o daemonize.o upnpglobalvars.o \
           options.o upnppermissions.o minissdp.o natpmp.o \
           upnpevents.o

LNXOBJS = getifstats.o
XNATPMPOBJS = xnatpmp.o

ALLOBJS = $(BASEOBJS) $(LNXOBJS) $(XNATPMPOBJS)

LIBS = 

EXECUTABLES = miniupnpd miniupnpdctl

.PHONY:	all clean install depend genuuid

all:	$(EXECUTABLES)

clean:
	$(RM) $(ALLOBJS)
	$(RM) $(EXECUTABLES)
	$(RM) miniupnpdctl.o

install:	miniupnpd genuuid
	$(STRIP) miniupnpd
	$(INSTALL) -d $(SBININSTALLDIR)
	$(INSTALL) miniupnpd $(SBININSTALLDIR)
	$(INSTALL) -d $(ETCINSTALLDIR)
	$(INSTALL) --mode=0644 -b miniupnpd.conf $(ETCINSTALLDIR)
	$(INSTALL) -d $(PREFIX)/etc/init.d
	$(INSTALL) miniupnpd.init.d.script $(PREFIX)/etc/init.d/miniupnpd

# genuuid is using the uuidgen CLI tool which is part of libuuid
# from the e2fsprogs
genuuid:
	sed -i -e "s/^uuid=[-0-9a-f]*/uuid=`(genuuid||uuidgen) 2>/dev/null`/" miniupnpd.conf

miniupnpd:	$(BASEOBJS) $(LNXOBJS) $(XNATPMPOBJS) $(LIBS)

miniupnpdctl:	miniupnpdctl.o

config.h:	genconfig.sh
	./genconfig.sh

depend:	config.h
	makedepend -f$(MAKEFILE_LIST) -Y $(ALLOBJS:.o=.c) 2>/dev/null

# DO NOT DELETE

miniupnpd.o: config.h upnpglobalvars.h upnppermissions.h miniupnpdtypes.h
miniupnpd.o: upnphttp.h upnpdescgen.h miniupnpdpath.h getifaddr.h upnpsoap.h
miniupnpd.o: options.h minissdp.h upnpredirect.h daemonize.h upnpevents.h
miniupnpd.o: natpmp.h xnatpmp.h
upnphttp.o: config.h upnphttp.h upnpdescgen.h miniupnpdpath.h upnpsoap.h
upnphttp.o: upnpevents.h
upnpdescgen.o: config.h upnpdescgen.h miniupnpdpath.h upnpglobalvars.h
upnpdescgen.o: upnppermissions.h miniupnpdtypes.h upnpdescstrings.h
upnpsoap.o: config.h upnpglobalvars.h upnppermissions.h miniupnpdtypes.h
upnpsoap.o: upnphttp.h upnpsoap.h upnpreplyparse.h upnpredirect.h getifaddr.h
upnpsoap.o: getifstats.h
upnpreplyparse.o: upnpreplyparse.h minixml.h
minixml.o: minixml.h
upnpredirect.o: config.h upnpredirect.h upnpglobalvars.h upnppermissions.h
upnpredirect.o: miniupnpdtypes.h upnpevents.h xnatpmp.h
getifaddr.o: getifaddr.h
daemonize.o: daemonize.h config.h
upnpglobalvars.o: config.h upnpglobalvars.h upnppermissions.h
upnpglobalvars.o: miniupnpdtypes.h
options.o: options.h config.h upnppermissions.h upnpglobalvars.h
options.o: miniupnpdtypes.h
upnppermissions.o: config.h upnppermissions.h
minissdp.o: config.h upnpdescstrings.h miniupnpdpath.h upnphttp.h
minissdp.o: upnpglobalvars.h upnppermissions.h miniupnpdtypes.h minissdp.h
minissdp.o: codelength.h
natpmp.o: config.h natpmp.h upnpglobalvars.h upnppermissions.h
natpmp.o: miniupnpdtypes.h getifaddr.h upnpredirect.h xnatpmp.h
upnpevents.o: config.h upnpevents.h miniupnpdpath.h upnpglobalvars.h
upnpevents.o: upnppermissions.h miniupnpdtypes.h upnpdescgen.h
getifstats.o: getifstats.h config.h
upnpdescgen.o: config.h upnpdescgen.h miniupnpdpath.h upnpglobalvars.h
upnpdescgen.o: upnppermissions.h miniupnpdtypes.h upnpdescstrings.h
xnatpmp.o: xnatpmp.h
