#!/usr/bin/env python

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
#
"""
Extended NAT-PMP daemon

Francis_Dupont@isc.org, November 2009

Usage: [-d] -m minport -M maxport [-n natsrc]+
"""   

__version__ = '$Id: xpmpd.py 998 2010-11-24 15:06:10Z fdupont $'


import getopt
import heapq
import select
import socket
import struct
import sys
import syslog
import time

CLIENTS = {}
NATTED = {}
EXPIRES = {}
HEAP = []

def debug(msg):
    """debug helper"""
    syslog.syslog(syslog.LOG_DEBUG, msg)

class OutofResources(Exception):
    """out of resources exception"""
    pass

class UnavailablePort(Exception):
    """unavailable port exception"""
    pass

class Sockets(object):
    """hide some globals for sockets"""
    transid = 0
    nextlinebuf = ''
    pending = []
    aftr = None
    sock = None

class Mapping(object):
    """Port mapping"""
    __slots__ = ['client', 'src', 'sport', 'nport',
                 'expire', 'proto', 'companion', 'down']

    def __init__(self, client, nport, proto):
        """initializer"""
        self.client = client
        self.src = ''
        self.sport = 0
        self.nport = nport
        self.expire = 0
        self.proto = proto
        self.companion = True
        self.down = False

    def hold(self):
        """hold down a mapping"""
        self.down = True
        self.expire = int(time.time()) + 120
        heapq.heappush(HEAP, self.expire)
        if EXPIRES.get(self.expire) is None:
            EXPIRES[self.expire] = [self]
        else:
            EXPIRES[self.expire].append(self)

class Client(object):
    """Client"""
    __slots__ = ['ipv6', 'nsrc', 'start', 'mappings']

    def __init__(self, ipv6, nsrc):
        """initializer"""
        self.ipv6 = ipv6
        self.nsrc = nsrc
        self.start = int(time.time())
        self.mappings = []

    def sssoe(self):
        """seconds since start of epoch"""
        return int(time.time()) - self.start

    def getmap(self, nport, proto):
        """search the mapping with nport"""
        for mapping in self.mappings:
            if (mapping.nport == nport) and (mapping.proto == proto):
                return mapping

    def getsrc(self, src, sport, proto):
        """search the mapping with src/sport"""
        for mapping in self.mappings:
            if (mapping.src != src) or (mapping.proto != proto):
                continue
            if mapping.companion:
                continue
            if (mapping.sport == sport):
                return mapping

    def getcompanion(self, mapping):
        """get the companion of a mapping"""
        if mapping.proto == 1:
            cproto = 2
        else:
            cproto = 1
        candidate = self.getmap(mapping.nport, cproto)
        if candidate.companion:
            return candidate

    def delsrcall(self, src, proto):
        """delete all mappings for a source"""
        for mapping in list(self.mappings):
            if (mapping.src != src) or (mapping.proto != proto):
                continue
            if mapping.companion:
                continue
            if mapping.down:
                continue
            askdelsnat(self, mapping)
            if mapping.expire != 0:
                EXPIRES[mapping.expire].remove(mapping)
            mapping.hold()

    def delall(self, proto):
        """delete all mappings"""
        for mapping in list(self.mappings):
            if mapping.proto != proto:
                continue
            if mapping.companion:
                continue
            if mapping.down:
                continue
            askdelsnat(self, mapping)
            if mapping.expire != 0:
                EXPIRES[mapping.expire].remove(mapping)
            mapping.hold()

class Natsrc(object):
    """per natted address object, clients per IPv6, IPv6 or '' per port"""
    __slots__ = ['clients', 'ports']

    def __init__(self, minport, maxport):
        """initializer"""
        self.clients = {}
        self.ports = {}
        for i in xrange(minport, maxport + 1):
            self.ports[i] = ''

    def getfreeport(self):
        """get first free port"""
        for (port, addr) in self.ports.items():
            if addr == '':
                return port
        syslog.syslog(syslog.LOG_WARNING, "can't get a free port")
        raise OutofResources

class Natspec(object):
    """natted port spec"""
    __slots__ = ['port', 'locked']

    def __init__(self, port, locked):
        """initializer"""
        self.port = port
        self.locked = locked

    def set(self, port):
        """set method"""
        if self.locked:
            raise TypeError, 'locked Natspec'
        self.port = port

    def get(self):
        """get method"""
        return self.port

    def islocked(self):
        """is locked?"""
        return self.locked

def ask(cmd):
    """send a command to AFTR daemon"""
    Sockets.aftr.send(cmd + '\n')
    debug('sent to AFTR: %s' % cmd)

def getnextline(wait):
    """get next line from AFTR daemon"""
    if len(Sockets.nextlinebuf) == 0:
        if wait:
            (ready, _, _) = select.select([Sockets.aftr], [], [], 0.10)
            if len(ready) == 0:
                return ''
        Sockets.nextlinebuf = Sockets.aftr.recv(1024)
    if not '\n' in Sockets.nextlinebuf:
        ret = Sockets.nextlinebuf
        Sockets.nextlinebuf = ''
        return ret
    i = Sockets.nextlinebuf.index('\n') + 1
    ret = Sockets.nextlinebuf[:i]
    Sockets.nextlinebuf = Sockets.nextlinebuf[i:]
    if ret[-1:] == '\n':
        ret = ret[:-1]
    debug('received from AFTR: %s' % ret)
    return ret

def expect(text):
    """expect a text from AFTR daemon"""
    Sockets.transid += 1
    echo = 'echo ' + str(Sockets.transid)
    Sockets.aftr.send(echo + '\n')
    i = 5
    while i != 0:
        i -= 1
        got = getnextline(True)
        if len(got) == 0:
            continue
        if got[:len(text)] == text:
            debug("got expected '%s' from AFTR" % text)
            return (True, got[len(text):])
        if got == 'command failed':
            debug('got failure from AFTR')
            return (False, '')
        if got == echo:
            debug('got echo from AFTR')
            return (False, '')
        Sockets.pending.append(got)
    return (False, '')

def asktunnel(addr):
    """ask tunnel info"""
    ask('try tunnel ' + addr)
    (ret, nsrc) = expect('tunnel ' + addr + ' ')
    if ret:
        debug('tunnel %s %s' % (addr, nsrc))
    else:
        debug('tunnel %s failed?' % addr)
    return nsrc

def askdelsnat(client, mapping):
    """ask static NAT delete"""
    if mapping.proto == 1:
        proto = ' udp '
    else:
        proto = ' tcp '
    text = 'nat ' + client.ipv6 + proto + mapping.src + \
        ' ' + str(mapping.sport)
    ask('delete ' + text)
    syslog.syslog(syslog.LOG_NOTICE, 'del ' + text)

def askaddsnat(client, mapping):
    """ask static NAT add"""
    if mapping.proto == 1:
        proto = ' udp '
    else:
        proto = ' tcp '
    text = 'nat ' + client.ipv6 + proto + mapping.src + \
        ' ' + str(mapping.sport) + ' ' + client.nsrc + \
        ' ' + str(mapping.nport)
    ask('try ' + text)
    (ret, _) = expect(text)
    if ret:
        syslog.syslog(syslog.LOG_NOTICE, 'add ' + text)
    else:
        debug('add %s failed?' % text)
    return ret

def delclient(client):
    """delete a client"""
    ipv6 = client.ipv6
    natsrc = NATTED[client.nsrc]
    for mapping in client.mappings:
        if mapping.expire != 0:
            EXPIRES[mapping.expire].remove(mapping)
        if not mapping.companion:
            natsrc.ports[mapping.nport] = ''
    del natsrc.clients[ipv6]
    del CLIENTS[ipv6]

def getextaddr(ipv6):
    """get external address"""
    client = CLIENTS.get(ipv6)
    if client is not None:
        return client
    nsrc = asktunnel(ipv6)
    if nsrc != '':
        client = Client(ipv6, nsrc)
        CLIENTS[ipv6] = client
        NATTED[nsrc].clients[ipv6] = client
        return client
    debug("can't get external address for %s" % ipv6)

def expire1(mapping):
    """expire a mapping"""
    client = mapping.client
    debug('expire')
    if not mapping.down:
        askdelsnat(client, mapping)
    companion = client.getcompanion(mapping)
    if companion:
        client.mappings.remove(companion)
        client.mappings.remove(mapping)
        NATTED[client.nsrc].ports[mapping.nport] = ''
    else:
        mapping.companion = True

def delmapping(ipv6, src, sport, proto):
    """delete a mapping"""
    client = CLIENTS.get(ipv6)
    if client is None:
        debug("can't get client in delmapping for %s" % ipv6)
        return None
    mapping = client.getsrc(src, sport, proto)
    if mapping is None:
        debug('delmapping: no mapping')
        return client
    if mapping.down:
        debug('delmapping: on hold')
        return client
    askdelsnat(client, mapping)
    if mapping.expire != 0:
        EXPIRES[mapping.expire].remove(mapping)
    mapping.hold()
    debug('delmapping: hold')
    return client

def delsrcall(ipv6, src, proto):
    """delete all mappings for a source"""
    client = CLIENTS.get(ipv6)
    if client is not None:
        client.delsrcall(src, proto)
    return client

def delall(ipv6, proto):
    """delete all mappings for a client"""
    client = CLIENTS.get(ipv6)
    if client is not None:
        client.delall(proto)
    return client

def setmapping(ipv6, src, sport, natspec, life, proto):
    """set a mapping"""
    client = CLIENTS.get(ipv6)
    if client is None:
        debug("can't get client in setmapping for %s" % ipv6)
        return None
    natsrc = NATTED[client.nsrc]
    nport = natspec.get()
    mapping = client.getsrc(src, sport, proto)
    if (mapping is not None) and (nport != mapping.nport):
        if natspec.islocked():
            raise UnavailablePort
        natspec.set(mapping.nport)
        return setmapping(ipv6, src, sport, natspec, life, proto)
    if nport == 0:
        if natspec.islocked():
            raise UnavailablePort
        natspec.set(natsrc.getfreeport())
        return setmapping(ipv6, src, sport, natspec, life, proto)
    holder = None
    hentry = natsrc.ports.get(nport)
    if (hentry is not None) and (hentry != ''):
        holder = natsrc.clients[hentry]
    if (hentry is None) or ((holder is not None) and (holder != client)):
        if natspec.islocked():
            raise UnavailablePort
        natspec.set(natsrc.getfreeport())
        return setmapping(ipv6, src, sport, natspec, life, proto)
    if holder is None:
        if len(client.mappings) >= 64:
            raise OutofResources
        mapping = Mapping(client, nport, proto)
        mapping.src = src
        mapping.sport = sport
        if askaddsnat(client, mapping):
            mapping.companion = False
            mapping.expire = int(time.time()) + life
            heapq.heappush(HEAP, mapping.expire)
            if EXPIRES.get(mapping.expire) is None:
                EXPIRES[mapping.expire] = [mapping]
            else:
                EXPIRES[mapping.expire].append(mapping)
            client.mappings.append(mapping)
            if proto == 1:
                other = 2
            else:
                other = 1
            companion = Mapping(client, nport, other)
            companion.src = src
            client.mappings.append(companion)
            natsrc.ports[nport] = ipv6
            debug('setmapping: new')
            return client
        else:
            debug('setmapping: failed (new)')
            return None
    # else holder == client
    mapping = client.getmap(nport, proto)
    if mapping.src != src:
        if natspec.islocked():
            raise UnavailablePort
        natspec.set(natsrc.getfreeport())
        return setmapping(ipv6, src, sport, natspec, life, proto)
    if mapping.companion:
        mapping.sport = sport
        if askaddsnat(client, mapping):
            mapping.companion = False
            mapping.expire = int(time.time()) + life
            heapq.heappush(HEAP, mapping.expire)
            if EXPIRES.get(mapping.expire) is None:
                EXPIRES[mapping.expire] = [mapping]
            else:
                EXPIRES[mapping.expire].append(mapping)
            debug('setmapping: promote companion')
            return client
        else:
            mapping.sport = 0
            debug('setmapping: failed (companion)')
            return None
    # else not mapping.companion
    if mapping.down:
        mapping.down = False
        mapping.sport = sport
    elif mapping.sport != sport:
        if natspec.islocked():
            raise UnavailablePort
        natspec.set(natsrc.getfreeport())
        return setmapping(ipv6, src, sport, natspec, life, proto)
    askaddsnat(client, mapping)
    if mapping.expire != 0:
        EXPIRES[mapping.expire].remove(mapping)
    mapping.expire = int(time.time()) + life
    heapq.heappush(HEAP, mapping.expire)
    if EXPIRES.get(mapping.expire) is None:
        EXPIRES[mapping.expire] = [mapping]
    else:
        EXPIRES[mapping.expire].append(mapping)
    debug('setmapping: renew')
    return client

def sendresp(sockaddr, response):
    """send the answer"""
    debug('sendresp')
    Sockets.sock.sendto(response, sockaddr)

def senderr(error, sockaddr, packet):
    """send an error"""
    (shimlen,) = struct.unpack('!B', packet[:1])
    response = packet[:shimlen]
    packet = packet[shimlen:]
    (version, opcode) = struct.unpack('!BB', packet[:2])
    response += struct.pack('!BB', version, opcode + 128)
    response += struct.pack('!H', error)
    if len(packet) > 4:
        client = CLIENTS.get(sockaddr[0])
        if client is not None:
            response += struct.pack('!I', client.sssoe())
            response += packet[4:]
    debug('senderr')
    Sockets.sock.sendto(response, sockaddr)

def getrequest(sockaddr, request):
    """decode a request"""
    ipv6 = sockaddr[0]
    packet = request
    (shimlen,) = struct.unpack('!B', packet[:1])
    if (shimlen < 5) or (shimlen + 2 > len(packet)):
        debug('bad shim (%d)' % shimlen)
        return
    shim = packet[:shimlen]
    packet = packet[shimlen:]
    binsrc = shim[-4:]
    src = socket.inet_ntoa(binsrc)
    (version, opcode) = struct.unpack('!BB', packet[:2])
    if version != 0:
        senderr(1, sockaddr, request[:shimlen + 2])
        return
    if opcode == 0:
        if len(packet) != 2:
            debug('bad get external address')
            return
        client = getextaddr(ipv6)
        if client is None:
            debug("can't find client from getextaddr: %s" % ipv6)
            return
        response = shim
        response += struct.pack('!BBHI', 0, 128, 0, client.sssoe())
        response += socket.inet_aton(client.nsrc)
        sendresp(sockaddr, response)
    elif (opcode == 1) or (opcode == 2) or (opcode == 3) or (opcode == 4):
        if len(packet) != 12:
            debug('bad set mapping')
            return
        packet = packet[4:]
        (sport, nport, life) = struct.unpack('!HHI', packet)
        if opcode == 1:
            proto = 1
            locked = False
        elif opcode == 2:
            proto = 2
            locked = False
        elif opcode == 3:
            proto = 1
            locked = True
        else:
            proto = 2
            locked = True
        if life == 0:
            nport = 0
            if sport == 0:
                if src == '0.0.0.0':
                    client = delall(ipv6, proto)
                    if client is None:
                        debug("can't find client for delall: %s" % ipv6)
                        return
                else:
                    client = delsrcall(ipv6, src, proto)
                    if client is None:
                        debug("can't find client for delsrcall: %s" % ipv6)
                        return
            else:
                client = delmapping(ipv6, src, sport, proto)
                if client is None:
                    debug("can't find client for delmapping: %s" % ipv6)
                    return
            response = shim
            response += struct.pack('!BB', 0, opcode + 128)
            response += struct.pack('!HI', 0, client.sssoe())
            response += packet
            sendresp(sockaddr, response)
            return
        else:
            natspec = Natspec(nport, locked)
            if life > 86400:
                life = 86400
            try:
                client = setmapping(ipv6, src, sport, natspec, life, proto)
            except OutofResources:
                senderr(4, sockaddr, request)
                return
            except UnavailablePort:
                senderr(6, sockaddr, request)
                return
            if client is None:
                debug("can't find client for setmapping: %s" % ipv6)
                return
            response = shim
            response += struct.pack('!BB', 0, opcode + 128)
            response += struct.pack('!HI', 0, client.sssoe())
            response += struct.pack('!HHI', sport, natspec.get(), life)
            sendresp(sockaddr, response)
            return
    else:
        senderr(5, sockaddr, request[:shimlen + 2])
        return

def expire():
    """expire routine"""
    now = int(time.time())
    while len(HEAP) > 0:
        first = HEAP[0]
        if first > now:
            return
        while (len(HEAP) > 0) and (first == HEAP[0]):
            heapq.heappop(HEAP)
        for mapping in EXPIRES[first]:
            expire1(mapping)
        del EXPIRES[first]

def checkdeltunnel(got):
    """check for a 'tunnel del ' notification"""
    text = 'tunnel del '
    if got[:len(text)] != text:
        return
    ipv6 = got[len(text):]
    client = CLIENTS.get(ipv6)
    if client is None:
        return
    syslog.syslog(syslog.LOG_NOTICE, 'delete client %s' % ipv6)
    delclient(client)

def mainloop():
    """main loop"""
    while True:
        expire()
        while len(Sockets.pending) > 0:
            checkdeltunnel(Sockets.pending.pop(0))
        (ready, _, _) = select.select([Sockets.aftr, Sockets.sock],
                                      [], [], 1.0)
        if Sockets.aftr in ready:
            got = getnextline(False)
            if len(got) == 0:
                syslog.syslog(syslog.LOG_CRIT,
                              'AFTR daemon connection closed')
                sys.exit(0)
            checkdeltunnel(got)
            continue
        if Sockets.sock in ready:
            (packet, sockaddr) = Sockets.sock.recvfrom(128)
            debug('got request from %s' % sockaddr[0])
            getrequest(sockaddr, packet)

def main(args):
    """main"""
    logopt = syslog.LOG_NDELAY
    minport = 0
    maxport = 0
    heapq.heapify(HEAP)
    try:
        opts, argv = getopt.getopt(args[1:], 'dn:m:M:')
    except getopt.GetoptError:
        print 'usage:', args[0], '[-d] -m minport -M maxport [-n natsrc]+'
        raise
    for opt, arg in opts:
        if opt == '-d':
            logopt += syslog.LOG_PERROR
            continue
        if opt == '-m':
            minport = int(arg)
            continue
        elif opt == '-M':
            maxport = int(arg)
            continue
        elif opt == '-n':
            if (minport == 0) or (maxport == 0):
                print args[0] + ':', 'needs max/minport'
                sys.exit(1)
            NATTED[arg] = Natsrc(minport, maxport)
            continue
    if len(NATTED) == 0:
        print args[0] + ':', 'needs at least one natsrc'
        sys.exit(1)
    if len(argv) != 0:
        print args[0] + ':', 'extra arguments:', argv[0] + ',', '...'
        sys.exit(1)

    syslog.openlog('xpmpd', logopt, syslog.LOG_LOCAL6)
    Sockets.aftr = socket.socket(socket.AF_INET,
                                 socket.SOCK_STREAM,
                                 socket.IPPROTO_TCP)
    Sockets.aftr.connect(('127.0.0.1', 1015))
    ask('session log off')
    ask('session notify on')
    ask('session config on')
    ask('session name xpmpd')
    Sockets.sock = socket.socket(socket.AF_INET6,
                                 socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
    Sockets.sock.bind(('::', 5351))

    mainloop()


main(sys.argv)
