#!/usr/bin/env python

# Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
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
#

"""
Client side of AFTR remote configuration

aftrconf-client <aftr-addr> <command>

commands:
create <user-ipv6> <protocol> <src-ipv4> <src-port> <nat-ipv4> <nat-port>
create <user-ipv6> <nat-ipv4>
delete <user-ipv6> <protocol> <src-ipv4> <src-port> <nat-ipv4> <nat-port>
delete <user-ipv6> <protocol> <src-ipv4> <src-port>
delete <protocol> <nat-ipv4> <nat-port>
delete <user-ipv6>
flush
get <user-ipv6>
get
"""

__version__ = '$Id: xmlclient.py 945 2010-10-19 20:53:12Z pselkirk $'

import sys
import socket
from lxml import etree

TRANSPORT = 'http'
#TRANSPORT = 'socket'
#TRANSPORT = 'debug'

NSMAP = {'aftr': 'http://aftr.isc.org/mapping/1.0'}

SOCKPORT = 4146
HTTPPORT = 4148

VERBOSE = False

def debug(msg):
    """debug helper"""
    if VERBOSE:
        print msg

if TRANSPORT == 'socket':
    SOCK = None

    def send(addr, request):
        """ send <rpc> request """
        global SOCK
        if SOCK is None:
            addrlist = socket.getaddrinfo(addr, SOCKPORT)
            try:
                SOCK = socket.socket(addrlist[0][0],
                                     socket.SOCK_STREAM,
                                     socket.IPPROTO_TCP)
            except socket.error as err:
                print 'ERROR:', err[1]
                exit()
            try:
                SOCK.connect(addrlist[0][4])
            except socket.error as err:
                print 'ERROR:', err[1]
                exit()
        try:
            SOCK.sendall(etree.tostring(request,
                                     encoding='UTF-8',
                                     xml_declaration=True,
                                     pretty_print=True))
        except socket.error as err:
            print 'ERROR:', err[1]
            exit()
        response = ''
        while True:
            try:
                buf = SOCK.recv(1024)
                if len(buf) == 0:
                    break
                response += buf
            except socket.error:
                # host unreachable, connection refused, etc
                pass
        processresponse(response)

elif TRANSPORT == 'http':
    import httplib
    CONN = None

    def send(addr, request):
        """ send <rpc> request """
        global CONN
        if CONN is None:
            addrlist = socket.getaddrinfo(addr, HTTPPORT)
            try:
                CONN = httplib.HTTPConnection(addrlist[0][4][0],
                                              addrlist[0][4][1])
            except socket.error as err:
                print 'ERROR:', err[1]
                exit()
        try:
            CONN.request('POST', '',
                         etree.tostring(request, pretty_print=True))
        except socket.error as err:
            print 'ERROR:', err[1]
            exit()
        response = CONN.getresponse()
        debug('%s %s' % (response.status, response.reason))
        buf = response.read()
        processresponse(buf)

else:	# TRANSPORT == 'debug'
    def send(addr, request):
        """ send <rpc> request """
        print 'addr:', addr
        # debugging: just print the request
        # (this can be piped to the server)
        print etree.tostring(request,
                             encoding='UTF-8',
                             xml_declaration=True,
                             pretty_print=True)

def processresponse(response):
    """process the response"""
    parser = etree.XMLParser(remove_blank_text=True,
                             remove_comments=True)
    try:
        #debug(response)
        root = etree.fromstring(response, parser)
    except etree.XMLSyntaxError:
        # XXX syslog?
        print 'error parsing response'
        raise
    if root.tag != 'rpc-reply':
        print 'invalid document from aftr:'
        print etree.tostring(root,
                             encoding='UTF-8',
                             xml_declaration=True,
                             pretty_print=True)
    else:
        for entry in root:
            if entry.tag == 'ok':
                print 'ok'
            elif entry.tag == 'rpc-error':
                print entry.text
            elif entry.tag == 'conf':
                for elem in entry:
                    if elem.tag == 'tunnelEntry':
                        tunnel = elem.find('tunnel')
                        addr = elem.find('nattedAddress')
                        if (tunnel is None) or (addr is None):
                            debug('missing element')
                            continue
                        print 'tunnel', tunnel.text, addr.text
                    elif elem.tag == 'natEntry':
                        tunnel = elem.find('tunnel')
                        proto = elem.find('protocol')
                        saddr = elem.find('sourceAddress')
                        sport = elem.find('sourcePort')
                        naddr = elem.find('nattedAddress')
                        nport = elem.find('nattedPort')
                        if (tunnel is None) or (proto is None) or \
                                (saddr is None) or (sport is None) or \
                                (naddr is None) or (nport is None):
                            debug('missing element')
                            continue
                        print 'nat', tunnel.text, proto.text, \
                            saddr.text, sport.text, naddr.text, nport.text
                    else:
                        print 'unexpected <conf> content: ', elem.tag
                        continue
            else:
                print 'unexpected rpc-reply:'
                print etree.tostring(entry,
                                     encoding='UTF-8',
                                     xml_declaration=True,
                                     pretty_print=True)

def parsecreate(args, request):
    """ parse a create command """
    # multiple forms of create:
    if len(args) == 6:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'create')
        etree.SubElement(operation, 'tunnel').text = args[0]
        etree.SubElement(operation, 'protocol').text = args[1]
        etree.SubElement(operation, 'sourceAddress').text = args[2]
        etree.SubElement(operation, 'sourcePort').text = args[3]
        etree.SubElement(operation, 'nattedAddress').text = args[4]
        etree.SubElement(operation, 'nattedPort').text = args[5]
    elif len(args) == 2:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'create')
        etree.SubElement(operation, 'tunnel').text = args[0]
        etree.SubElement(operation, 'nattedAddress').text = args[1]
    else:
        print 'usage: create <user-ipv6> <protocol>', \
            '<src-ipv4> <src-port> <nat-ipv4> <nat-port>\n', \
            '       create <user-ipv6> <nat-ipv4>'
        return False
    return True

def parsedelete(args, request):
    """ parse a delete command """
    # multiple forms of delete:
    if len(args) == 6:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'delete')
        etree.SubElement(operation, 'tunnel').text = args[0]
        etree.SubElement(operation, 'protocol').text = args[1]
        etree.SubElement(operation, 'sourceAddress').text = args[2]
        etree.SubElement(operation, 'sourcePort').text = args[3]
        etree.SubElement(operation, 'nattedAddress').text = args[4]
        etree.SubElement(operation, 'nattedPort').text = args[5]
    elif len(args) == 4:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'delete')
        etree.SubElement(operation, 'tunnel').text = args[0]
        etree.SubElement(operation, 'protocol').text = args[1]
        etree.SubElement(operation, 'sourceAddress').text = args[2]
        etree.SubElement(operation, 'sourcePort').text = args[3]
    elif len(args) == 3:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'delete')
        etree.SubElement(operation, 'protocol').text = args[0]
        etree.SubElement(operation, 'nattedAddress').text = args[1]
        etree.SubElement(operation, 'nattedPort').text = args[2]
    elif len(args) == 1:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'delete')
        etree.SubElement(operation, 'tunnel').text = args[0]
    else:
        print 'usage: delete <user-ipv6> <protocol> <src-ipv4> ', \
            '<src-port> <nat-ipv4> <nat-port>\n', \
            '       delete <user-ipv6> <protocol> <src-ipv4> <src-port>\n', \
            '       delete <protocol> <nat-ipv4> <nat-port>\n', \
            '       delete <user-ipv6>'
        return False
    return True

def parseflush(args, request):
    """ parse a flush command """
    if len(args) != 0:
        print 'usage: flush'
        return False
    etree.SubElement(request, 'flush')
    return True

def parseget(args, request):
    """ parse a get command """
    # two forms of get:
    if len(args) == 1:
        # XXX sanity check args?
        operation = etree.SubElement(request, 'get')
        operation.set('tunnel', args[0])
    elif len(args) == 0:
        etree.SubElement(request, 'get')
    else:
        print 'usage: get [tunnel]'
        return False
    return True

def dispatch(args):
    """parse and send one command to the aftr"""
    request = etree.Element('rpc', nsmap=NSMAP)
    if args[2] == 'create':
        ret = parsecreate(args[3:], request)
    elif args[2] == 'delete':
        ret = parsedelete(args[3:], request)
    elif args[2] == 'get':
        ret = parseget(args[3:], request)
    elif args[2] == 'flush':
        ret = parseflush(args[3:], request)
    else:
        print 'unknown command "%s"' % args[2]
        ret = False
    if ret:
        send(args[1], request)

def main(args):
    """main"""
    if len(args) < 2:
        print 'usage:', args[0], '<aftr-addr> get|create|delete|flush'
        return
    if len(args) == 2:
        # read commands from a script file
        for line in sys.stdin:
            print '[' + line.strip() + ']'
            largs = line.split()
            # skip blank lines
            if len(largs) < 1:
                continue
            dispatch(args + largs)
    else:
        # single command
        dispatch(args)

main(sys.argv)
