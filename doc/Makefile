# Copyright (C) 2009-2010  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: Makefile 1003 2010-12-13 21:55:51Z pselkirk $

VERSION='1.1'

TOPDIR=..
MANDIR=${TOPDIR}/man
HTMLDIR=${TOPDIR}/html

MANPAGES= ${MANDIR}/aftr.8 ${MANDIR}/aftr.conf.5 ${MANDIR}/aftr.commands.5 \
	${MANDIR}/xmlconf.8 ${MANDIR}/xmlclient.8
HTMLPAGES= ${HTMLDIR}/aftr.html ${HTMLDIR}/aftr.conf.html \
	${HTMLDIR}/aftr.commands.html \
	${HTMLDIR}/xmlconf.html ${HTMLDIR}/xmlclient.html \
	${HTMLDIR}/book.html
MANOBJS= ${MANPAGES} ${HTMLPAGES}
DOCOBJS= ${TOPDIR}/book.pdf ${TOPDIR}/book.txt

MANSRCS= aftr.docbook aftr.conf.docbook aftr.commands.docbook \
	xmlconf.docbook xmlclient.docbook
BOOKSRCS= book.xml releaseinfo.xml ${MANSRCS}

man: ${MANOBJS}
doc: ${DOCOBJS} ${MANOBJS}

clean:
	rm -f releaseinfo.xml *.8 *.5 *.html

all: doc

XSLTPROC=	xsltproc --novalid --xinclude --nonet
DBLATEX=	dblatex -d -V

.SUFFIXES: .docbook .html .5 .8

.docbook.html:
	${XSLTPROC} -o $@ xsl/isc-docbook-html.xsl $<

.docbook.5:
	${XSLTPROC} -o $@ xsl/isc-manpage.xsl $<

.docbook.8:
	${XSLTPROC} -o $@ xsl/isc-manpage.xsl $<

manclean:
	rm -f ${MANOBJS}

docclean:
	rm -f ${DOCOBJS} ${MANOBJS}

${MANDIR}/aftr.8: aftr.8
	cp aftr.8 ${MANDIR}/aftr.8

${MANDIR}/aftr.conf.5: aftr.conf.5
	cp aftr.conf.5 ${MANDIR}/aftr.conf.5

${MANDIR}/aftr.commands.5: aftr.commands.5
	cp aftr.commands.5 ${MANDIR}/aftr.commands.5

${MANDIR}/xmlconf.8: xmlconf.8
	cp xmlconf.8 ${MANDIR}/xmlconf.8

${MANDIR}/xmlclient.8: xmlclient.8
	cp xmlclient.8 ${MANDIR}/xmlclient.8

${HTMLDIR}/aftr.html: aftr.html
	cp aftr.html ${HTMLDIR}/aftr.html

${HTMLDIR}/aftr.conf.html: aftr.conf.html
	cp aftr.conf.html ${HTMLDIR}/aftr.conf.html

${HTMLDIR}/aftr.commands.html: aftr.commands.html
	cp aftr.commands.html ${HTMLDIR}/aftr.commands.html

${HTMLDIR}/xmlconf.html: xmlconf.html
	cp xmlconf.html ${HTMLDIR}/xmlconf.html

${HTMLDIR}/xmlclient.html: xmlclient.html
	cp xmlclient.html ${HTMLDIR}/xmlclient.html

${HTMLDIR}/book.html: ${BOOKSRCS}
	expand book.xml | \
	${XSLTPROC} -o ${HTMLDIR}/book.html xsl/isc-docbook-html.xsl -

${TOPDIR}/book.pdf: ${BOOKSRCS}
	${DBLATEX} -p xsl/isc-docbook-dblatex.xsl \
	-o ${TOPDIR}/book.pdf book.xml

${TOPDIR}/book.txt: ${BOOKSRCS}
	expand book.xml | \
	${XSLTPROC} -o - xsl/isc-docbook-text.xsl - | \
	lynx -stdin -dump -nolist > ${TOPDIR}/book.txt

releaseinfo.xml:
	echo >$@ '<releaseinf>AFTR Version ${VERSION}</releaseinfo>'
