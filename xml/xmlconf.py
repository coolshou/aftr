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
AFTR remote configuration server

aftrconf [-l local-addr] [-p local-port] [-r remote-addr] [-c config-file] [-v]
"""
__version__ = '$Id: xmlconf.py 945 2010-10-19 20:53:12Z pselkirk $'

import sys
import time
import socket
import getopt
import shutil
from lxml import etree

TRANSPORT = 'http'
#TRANSPORT = 'socket'
#TRANSPORT = 'debug'

################ mutable globals ################

class MutableGlobal(object):
    """mutable global"""
    __slots__ = ['value']
    __hash__ = None

    def __init__(self, value=None):
        """initializer"""
        self.value = value

    def get(self):
        """get value"""
        return self.value

    def set(self, value):
        """set value"""
        self.value = value

################ configuration dicts ################

class NatEntry(object):
    """static NAT entry"""
    __slots__ = ['parent', 'protocol', 'saddr', 'sport', 'nport']
    __hash__ = None

    def __init__(self, parent, protocol, saddr, sport, nport):
        """initializer"""
        self.parent = parent
        self.protocol = protocol
        self.saddr = saddr
        self.sport = sport
        self.nport = nport

    def __eq__(self, other):
        """equality"""
        if not isinstance(other, NatEntry):
            return False
        if self.saddr != other.saddr:
            return False
        if self.sport != other.sport:
            return False
        if self.protocol != other.protocol:
            return False
        if self.nport != other.nport:
            return False
        return True

    def __ne__(self, other):
        """inequality"""
        return not self.__eq__(other)

    def __cmp__(self, other):
        """compare"""
        if self == other:
            return 0
        if not isinstance(other, NatEntry):
            return 1
        key1 = socket.inet_pton(socket.AF_INET, self.saddr)
        key2 = socket.inet_pton(socket.AF_INET, other.saddr)
        if key1 != key2:
            return cmp(key1, key2)
        if self.sport != other.sport:
            return cmp(self.sport, other.sport)
        if self.protocol != other.protocol:
            return cmp(self.protocol, other.protocol)
        if self.nport != other.nport:
            return cmp(self.nport, other.nport)
        raise ValueError, 'NatEntry.__cmp__'

    def totext(self, file_):
        """export to text"""
        print >> file_, 'nat', self.parent.remote, self.protocol, self.saddr, \
            self.sport, self.parent.addr, self.nport

    def toxml(self, parent):
        """export to xml"""
        nat = etree.SubElement(parent, 'natEntry')
        etree.SubElement(nat, 'tunnel').text = self.parent.remote
        etree.SubElement(nat, 'protocol').text = self.protocol
        etree.SubElement(nat, 'sourceAddress').text = self.saddr
        etree.SubElement(nat, 'sourcePort').text = self.sport
        etree.SubElement(nat, 'nattedAddress').text = self.parent.addr
        etree.SubElement(nat, 'nattedPort').text = self.nport

    def hashkey_src(self):
        """src kind of hash key"""
        return (self.parent.remote, self.saddr, self.sport, self.protocol)

    def hashkey_nat(self):
        """nat kind of hash key"""
        return (self.parent.addr, self.nport, self.protocol)

class Tunnel(object):
    """tunnel entry"""
    __slots__ = ['remote', 'addr', 'policies', 'entries']
    __hash__ = None

    def __init__(self, remote, addr):
        """initializer"""
        self.remote = remote
        self.addr = addr
        self.policies = {}
        self.entries = []

    def __eq__(self, other):
        """shallow equality"""
        if not isinstance(other, Tunnel):
            return False
        if self.remote != other.remote:
            return False
        if self.addr != other.addr:
            return False
        return True

    def __ne__(self, other):
        """shallow inequality"""
        return not self.__eq__(other)

    def __cmp__(self, other):
        """compare"""
        if self == other:
            return 0
        if not isinstance(other, Tunnel):
            return 1
        key1 = socket.inet_pton(socket.AF_INET6, self.remote)
        key2 = socket.inet_pton(socket.AF_INET6, other.remote)
        if key1 != key2:
            return cmp(key1, key2)
        if not isinstance(other, Tunnel):
            return 1
        key1 = socket.inet_pton(socket.AF_INET, self.addr)
        key2 = socket.inet_pton(socket.AF_INET, other.addr)
        if key1 != key2:
            return cmp(key1, key2)
        raise ValueError, 'Tunnel.__cmp__'

    def totext(self, file_):
        """export to text"""
        if len(self.entries) == 0:
            print >> file_, 'tunnel', self.remote, self.addr
        else:
            for entry in self.entries:
                entry.totext(file_)
        for name, value in self.policies.iteritems():
            print >> file_, name, self.remote, value

    def toxml(self, parent):
        """export to xml"""
        if len(self.entries) == 0:
            tun = etree.SubElement(parent, 'tunnelEntry')
            etree.SubElement(tun, 'tunnel').text = self.remote
            etree.SubElement(tun, 'nattedAddress').text = self.addr
        else:
            for entry in self.entries:
                entry.toxml(parent)
        for name, value in self.policies.iteritems():
            pol = etree.SubElement(parent, 'tunnelPolicy')
            etree.SubElement(pol, 'tunnel').text = self.remote
            etree.SubElement(pol, 'policyName').text = name
            etree.SubElement(pol, 'policyValue').text= value

class PoolAddr(object):
    """ information about a managed IPv4 address """
    __slots__ = ['addr', 'tcpmin', 'tcpmax', 'udpmin', 'udpmax']
    # each pool could have a dict of assigned tunnels,
    # if we ever wanted to look things up that way

    def __init__(self, addr, tcpmin, tcpmax, udpmin, udpmax):
        """initializer"""
        self.addr = addr
        self.tcpmin = tcpmin
        self.tcpmax = tcpmax
        self.udpmin = udpmin
        self.udpmax = udpmax

    def totext(self, file_):
        """export to text"""
        if self.addr == 'default':
            print >> file_, 'default', 'pool', 'tcp', \
                str(self.tcpmin) + '-' + str(self.tcpmax)
            print >> file_, 'default', 'pool', 'udp', \
                str(self.udpmin) + '-' + str(self.udpmax)
        else:
            print >> file_, 'pool', self.addr, 'tcp', \
                str(self.tcpmin) + '-' + str(self.tcpmax)
            print >> file_, 'pool', self.addr, 'udp', \
                str(self.udpmin) + '-' + str(self.udpmax)

    def copy(self):
        """copy"""
        return PoolAddr(self.addr, self.tcpmin, self.tcpmax,
                        self.udpmin, self.udpmax)

class Conf(dict):
    """conf state as a dict extension"""

    def totext(self, file_):
        """export to text"""
        for elem in sorted(self.values()):
            elem.totext(file_)

    def toxml(self, parent):
        """export to xml"""
        for elem in sorted(self.values()):
            elem.toxml(parent)

    def gettunnel(self, ipv6, addr=None):
        """get or create a tunnel entry"""
        tunnel = self.get(ipv6)
        if tunnel is not None:
            if addr and (tunnel.addr != addr):
                raise ValueError, 'tunnel natted mismatch'
        elif addr is not None:
            tunnel = Tunnel(ipv6, addr)
            self[ipv6] = tunnel
        return tunnel

CONFNAT = {}
CONFTUN = Conf()

# default port ranges, from aftr.c
CONFPOOL = {'default': PoolAddr('default', 2048, 65535, 512, 65535)}

################ config file routines ################

CONFFILE = MutableGlobal()

RELOADIDLE = 30
RELOADBUSY = 180

def canonv4(text):
    """canonicalize an IPv4 address"""
    if text is None:
        return None
    try:
        addr = socket.inet_pton(socket.AF_INET, text)
        return socket.inet_ntop(socket.AF_INET, addr)
    except socket.error:
        #print 'canonv4 failed on', text
        return None

def canonv6(text):
    """canonicalize an IPv6 address"""
    if text is None:
        return None
    try:
        addr = socket.inet_pton(socket.AF_INET6, text)
        return socket.inet_ntop(socket.AF_INET6, addr)
    except socket.error:
        #print 'canonv6 failed on', text
        return None

def canonport(text):
    """canonicalize a port number"""
    try:
        port = int(text)
        if (port <= 0) or (port > 65535):
            return None
        return str(port)
    except ValueError:
        #print 'canonport failed on', text
        return None

def canonproto(text):
    """canonicalize a protocol name"""
    if (text == 'tcp') or (text == 'udp'):
        return text
    else:
        return None

def canonmtu(text):
    """canonicalize a MTU value"""
    try:
        mtu = int(text)
        if (mtu < 1280) or (mtu > 65535):
            return None
        return str(mtu)
    except ValueError:
        #print 'canonmtu failed on', text
        return None

class ConfigFile:
    """parse aftr.conf"""

    file_marker = '#### Everything below this line is ' + \
        'subject to rewriting by aftrconf.py ####'

    def __init__(self, name):
        """initializer - parse config file"""
        try:
            self.file = open(name, 'r+')
        except IOError as err:
            # most likely ENOENT - No such file or directory
            print err
            sys.exit(1)
        try:
            shutil.copy2(name, name + '~')
        except IOError as err:
            # most likely EACCES - Permission denied
            print err[1]
            sys.exit(1)
        self.file_rewrite = 0
        self.file_section2 = ''
        pos = 0
        while True:
            pos = self.file.tell()
            line = self.file.readline()
            if not line:
                break
            self.cf_parse_line(line.rstrip(), pos)
        # leave file open for rewriting
        #self.rewrite()
        self.reloadtime = int(time.time())
        self.dirty = False
        #debug_consistency()
        self.starttime = self.reloadtime

    def append(self, line):
        """append to config file"""
        self.file.write(line)
        self.file.flush()
        self.dirty = True

    def truncate(self):
        """truncate config file"""
        if self.file_rewrite > 0:
            self.file.seek(self.file_rewrite)
            self.file.truncate()
            self.file.write(self.file_marker + '\n')
            self.file.flush()
            self.dirty = True

    def rewrite(self):
        """rewrite config file"""
        debug('rewriting config')
        if self.file_rewrite == 0:
            # if there are no nat or tunnel commands, set the rewrite pointer
            # to the end of the file
            self.file_rewrite = self.file.tell()
        elif len(self.file_section2) > 0:
            # consolidate the non-nat section 2 commands
            self.file.seek(self.file_rewrite)
            self.file.truncate()
            self.file.write('#### The following commands were ' +
                             'relocated here by aftrconf.py ####\n')
            self.file.write(self.file_section2)
            self.file.write('\n')
            self.file_rewrite = self.file.tell()
            self.file_section2 = ''
        self.file.seek(self.file_rewrite)
        self.file.truncate()
        self.file.write(self.file_marker + '\n')
        CONFTUN.totext(self.file)
        #self.file.write('#### New commands since the last rewrite ####\n')
        self.file.flush()
        self.dirty = True

    def reload_idle_timeout(self):
        """reload config file on an idle timer"""
        # called by TCPServer or HTTPServer after 30 sec inactivity
        debug(str(int(time.time()) - self.starttime) + \
              ' reload_idle_timeout')
        if self.dirty:
            AFTRSOCK.get().askreload()
            self.dirty = False
        # set the last-reloaded time, even if we didn't actually need to
        # reload, so that the first request after an extended idle period
        # doesn't trigger the busy-reload timer
        self.reloadtime = int(time.time())

    def reload_busy_timeout(self):
        """reload config file on an absolute timer"""
        # called after every request to force a reload at least every 3 min
        if int(time.time()) - self.reloadtime > RELOADBUSY:
            debug(str(int(time.time()) - self.starttime) + \
                      ' reload_busy_timeout')
            if self.dirty:
                AFTRSOCK.get().askreload()
                self.dirty = False
            self.reloadtime = int(time.time())

    def cf_parse_line(self, text, file_pos):
        """parse a line"""
        if text == self.file_marker:
            if self.file_rewrite == 0:
                self.file_rewrite = file_pos
            return
        args = text.split()
        if len(args) != 0:
            if args[0] == 'pool':
                cf_parse_pool(args)
            elif args[0] == 'default' and args[1] == 'pool':
                cf_parse_defpool(args)
            elif args[0] == 'nat':
                if self.file_rewrite == 0:
                    self.file_rewrite = file_pos
                cf_parse_nat(args)
            elif args[0] == 'tunnel':
                if self.file_rewrite == 0:
                    self.file_rewrite = file_pos
                cf_parse_tunnel(args)
            elif (args[0] == 'mss' or
                  args[0] == 'mtu' or
                  args[0] == 'toobig'):
                cf_parse_policies(args)
            elif (args[0] == 'prr' or
                  args[0] == 'nonat' or
                  args[0] == 'debug'):
                if self.file_rewrite != 0:
                    self.file_section2 = self.file_section2 + text + '\n'

def cf_parse_defpool(args):
    """ parse a pool entry """
    if len(args) != 4:
        raise SyntaxError
    pool = CONFPOOL['default']
    dash = args[3].find('-')
    if dash < 0:
        raise SyntaxError
    min_ = args[3][0:dash]
    max_ = args[3][dash+1:]
    if args[2] == 'tcp':
        pool.tcpmin = min_
        pool.tcpmax = max_
    elif args[2] == 'udp':
        pool.udpmin = min_
        pool.udpmax = max_

def cf_parse_pool(args):
    """ parse a pool entry """
    if (len(args) != 2) and (len(args) != 4):
        raise SyntaxError
    addr = args[1]
    pool = CONFPOOL.get(addr)
    if pool is None:
        pool = CONFPOOL['default'].copy()
        pool.addr = addr
        CONFPOOL[addr] = pool
    if len(args) > 2:
        dash = args[3].find('-')
        if dash < 0:
            raise SyntaxError
        min_ = args[3][0:dash]
        max_ = args[3][dash+1:]
        if args[2] == 'tcp':
            pool.tcpmin = min_
            pool.tcpmax = max_
        elif args[2] == 'udp':
            pool.udpmin = min_
            pool.udpmax = max_

def cf_parse_nat(args):
    """parse a static NAT entry"""
    if len(args) != 7:
        raise SyntaxError
    remote = canonv6(args[1])
    if remote is None:
        raise SyntaxError(args[1])
    protocol = canonproto(args[2])
    if protocol is None:
        raise SyntaxError
    saddr = canonv4(args[3])
    if saddr is None:
        raise SyntaxError
    sport = canonport(args[4])
    if sport is None:
        raise SyntaxError
    naddr = canonv4(args[5])
    if naddr is None:
        raise SyntaxError
    nport = canonport(args[6])
    if naddr is None:
        raise SyntaxError
    parent = CONFTUN.gettunnel(remote, naddr)
    nat_entry = NatEntry(parent, protocol, saddr, sport, nport)
    parent.entries.append(nat_entry)
    CONFNAT[nat_entry.hashkey_src()] = nat_entry
    CONFNAT[nat_entry.hashkey_nat()] = nat_entry

def cf_parse_tunnel(args):
    """parse a tunnel entry"""
    if len(args) == 2:
        return
    if len(args) < 2:
        raise SyntaxError
    remote = canonv6(args[1])
    if remote is None:
        raise SyntaxError
    naddr = canonv4(args[2])
    if naddr is None:
        raise SyntaxError
    CONFTUN.gettunnel(remote, naddr)

def cf_parse_policies(args):
    """parse a mss, mtu, or toobig entry"""
    if len(args) != 3:
        raise SyntaxError(' '.join(args))
    remote = canonv6(args[1])
    if remote is None:
        raise SyntaxError(' '.join(args))
    tunnel = CONFTUN.gettunnel(remote)
    # might return None if tunnel has not been declared yet,
    # or has been declared without a natted IPv4 address
    if tunnel is not None:
        tunnel.policies[args[0]] = args[2]

################ rpc processing ################

NSMAP = {'aftr': 'http://aftr.isc.org/mapping/1.0'}

class RpcBinding(object):
    """ NAT binding information in an rpc request """
    __slots__ = ['tunnel', 'protocol', 'saddr', 'sport', 'naddr', 'nport']

    def __init__(self, element):
        """ initializer """
        self.tunnel = None
        self.protocol = None
        self.saddr = None
        self.sport = None
        self.naddr = None
        self.nport = None
        for entry in element:
            if entry.tag == 'tunnel':
                self.tunnel = canonv6(entry.text)
            elif entry.tag == 'protocol':
                self.protocol = canonproto(entry.text)
            elif entry.tag == 'sourceAddress':
                self.saddr = canonv4(entry.text)
            elif entry.tag == 'sourcePort':
                self.sport = canonport(entry.text)
            elif entry.tag == 'nattedAddress':
                self.naddr = canonv4(entry.text)
            elif entry.tag == 'nattedPort':
                self.nport = canonport(entry.text)
            # XXX else ignore unrecognized subelements?

    def incomplete(self):
        """incomplete entry"""
        return (self.tunnel is None or
                self.protocol is None or
                self.saddr is None or
                self.sport is None or
                self.naddr is None or
                self.nport is None)

    def incomplete_src(self):
        """incomplete src"""
        return (self.tunnel is None or
                self.protocol is None or
                self.saddr is None or
                self.sport is None)

    def incomplete_nat(self):
        """incomplete nat"""
        return (self.protocol is None or
                self.naddr is None or
                self.nport is None)

    def tunnelonly(self):
        """tunnel only"""
        return (self.tunnel is not None and
                self.protocol is None and
                self.saddr is None and
                self.sport is None and
                self.naddr is None and
                self.nport is None)

    def qualifiedtunnelonly(self):
        """qualified (by naddr) tunnel only"""
        return (self.tunnel is not None and
                self.protocol is None and
                self.saddr is None and
                self.sport is None and
                self.naddr is not None and
                self.nport is None)

    def hashkey_src(self):
        """src kind of hash key"""
        return (self.tunnel, self.saddr, self.sport, self.protocol)

    def hashkey_nat(self):
        """nat kind of hash key"""
        return (self.naddr, self.nport, self.protocol)

def addnat(binding):
    """add a static nat entry"""
    resp = AFTRSOCK.get().askaddnat(binding)
    if resp is False:
        return False
    parent = CONFTUN.gettunnel(binding.tunnel, binding.naddr)
    nat_entry = NatEntry(parent, binding.protocol, binding.saddr,
                         binding.sport, binding.nport)
    parent.entries.append(nat_entry)
    CONFNAT[nat_entry.hashkey_src()] = nat_entry
    CONFNAT[nat_entry.hashkey_nat()] = nat_entry
    # record new binding in the config file
    CONFFILE.get().append('nat %s %s %s %s %s %s\n' %
                    (binding.tunnel, binding.protocol, binding.saddr,
                     binding.sport, binding.naddr, binding.nport))
    #debug_consistency()
    return True

def delnat(nat_entry):
    """delete a static nat entry"""
    resp = AFTRSOCK.get().askdelnat(nat_entry)
    if resp is False:
        return False
    parent = nat_entry.parent
    parent.entries.remove(nat_entry)
    del CONFNAT[nat_entry.hashkey_src()]
    del CONFNAT[nat_entry.hashkey_nat()]
    del nat_entry
    # the nat entry will be removed from the config file on rewrite
    #debug_consistency()

def generror(reply, error):
    """generate an error"""
    msg = etree.SubElement(reply, 'rpc-error')
    msg.text = error
    return False

def genok(reply):
    """generate an ok"""
    etree.SubElement(reply, 'ok')
    return True

def rpc_parse(request):
    """parse a message from the provisioning system"""
    parser = etree.XMLParser(remove_blank_text=True,
                             remove_comments=True)
    try:
        root = etree.fromstring(request, parser)
    except etree.XMLSyntaxError:
        # XXX syslog?
        return 'error parsing request'
    reply = etree.Element('rpc-reply', attrib=root.attrib, nsmap=NSMAP)
    ret = rpc_request(root, reply)
    # if the config file has been changed, rewrite it
    if ret:
        CONFFILE.get().rewrite()
    return etree.tostring(reply, pretty_print=True)

def rpc_request(root, reply):
    """ parse <rpc> element """
    # returns an indication of whether the config file has changed
    if root.tag != 'rpc':
        return generror(reply,
                        'ERROR: invalid document: missing "rpc" element')
    if len(root) == 0:
        return generror(reply, 'ERROR: no operation')
    elif len(root) > 1:
        return generror(reply, 'ERROR: too many operations')
    entry = root[0]
    if entry.tag == 'flush':
        return rpc_flush(reply)
    elif entry.tag == 'create':
        return rpc_create(entry, reply)
    elif entry.tag == 'delete':
        return rpc_delete(entry, reply)
    elif entry.tag == 'get':
        rpc_get(entry, reply)
        return False	# don't need to rewrite config file
    else:
        return generror(reply, 'ERROR: unknown operation ' + entry.tag)

def rpc_create(entry, reply):
    """ parse <create> element """
    binding = RpcBinding(entry)
    # if any element is missing, ERROR
    if binding.incomplete() and not binding.qualifiedtunnelonly():
        return generror(reply, 'ERROR: malformed create request')
    pool = CONFPOOL.get(binding.naddr)
    # if nattedAddress is not in the managed pool, ERROR
    if pool is None:
        return generror(reply, 'ERROR: external address not managed')
    tunnel = CONFTUN.gettunnel(binding.tunnel)
    # if tunnel is not found, acquire or create it
    if tunnel is None:
        nsrc = AFTRSOCK.get().asktunnel(binding.tunnel, binding.naddr)
        if nsrc == binding.naddr:
            tunnel = CONFTUN.gettunnel(binding.tunnel, binding.naddr)
        else:
            if canonv4(nsrc) is not None:
                return generror(reply,
                                'ERROR: tunnel ' + binding.tunnel +
                                ' is already bound to nattedAddress ' + nsrc)
            else:
                return generror(reply,
                                'ERROR: tunnel ' + binding.tunnel +
                                ' create failed: ' + nsrc)
    else:
        # if nattedAddress does not match tunnel, ERROR
        if tunnel.addr != binding.naddr:
            return generror(reply,
                            'ERROR: tunnel ' + binding.tunnel +
                            ' is already bound to nattedAddress ' +
                            tunnel.addr)
    if binding.qualifiedtunnelonly():
        return genok(reply)
    # if nattedPort out of range, ERROR
    if binding.protocol == 'tcp':
        if (int(binding.nport) >= int(pool.tcpmin) and
            int(binding.nport) <= int(pool.tcpmax)):
            return generror(reply, 'ERROR: external port out-of-range')
    elif binding.protocol == 'udp':
        if (int(binding.nport) >= int(pool.udpmin) and
            int(binding.nport) <= int(pool.udpmax)):
            return generror(reply, 'ERROR: external port out-of-range')
    entry_by_src = CONFNAT.get(binding.hashkey_src())
    entry_by_nat = CONFNAT.get(binding.hashkey_nat())
    # both = None: no existing nat binding
    # only entry_by_src set:
    # only entry_by_nat set:
    # both set, not equal
    # both set, equal
    if entry_by_src is not None:
        if entry_by_src == entry_by_nat:
            # if full binding exists, return <ok>
            genok(reply)
            return False	# don't need to rewrite config file
        elif entry_by_nat and (entry_by_nat.parent != entry_by_src.parent):
            # if port bound to a different tunnel, ERROR
            return generror(reply,
                            'ERROR: port assigned to another subscriber')
        else:
            # if src is bound to another port, delete then add
            delnat(entry_by_src)
            addnat(binding)
            return genok(reply)
    elif entry_by_nat is not None:
        if entry_by_nat.parent.remote != binding.tunnel:
            # if port bound to a different tunnel, ERROR
            return generror(reply,
                            'ERROR: port assigned to another subscriber')
        else:
            # if port is bound to a different src, delete then add
            delnat(entry_by_nat)
            addnat(binding)
            return genok(reply)
    else:
        addnat(binding)
        return genok(reply)

def rpc_delete(entry, reply):
    """ parse <delete> element """
    binding = RpcBinding(entry)
    if binding.tunnelonly():
        # delete the whole tunnel
        tunnel = CONFTUN.gettunnel(binding.tunnel)
        if tunnel is not None:
            resp = AFTRSOCK.get().askdeltunnel(tunnel.remote)
            if resp != 'OK':
                return generror(reply, 'ERROR: ' + resp)
            while tunnel.entries:
                nat_entry = tunnel.entries.pop()
                del CONFNAT[nat_entry.hashkey_src()]
                del CONFNAT[nat_entry.hashkey_nat()]
                del nat_entry
            del CONFTUN[binding.tunnel]
            del tunnel
            #debug_consistency()
            return genok(reply)
        else:
            return generror(reply, 'ERROR: no tunnel found')
    elif not binding.incomplete():
        nat_entry = CONFNAT.get(binding.hashkey_src())
        if nat_entry != CONFNAT.get(binding.hashkey_nat()):
            return generror(reply, 'ERROR: no mapping found')
    elif not binding.incomplete_src():
        nat_entry = CONFNAT.get(binding.hashkey_src())
    elif not binding.incomplete_nat():
        nat_entry = CONFNAT.get(binding.hashkey_nat())
    else:
        return generror(reply, 'ERROR: malformed delete request')
    if nat_entry is None:
        return generror(reply, 'ERROR: no mapping found')
    delnat(nat_entry)
    return genok(reply)

def rpc_get(entry, reply):
    """ parse <get> element """
    remote = canonv6(entry.get('tunnel'))
    if remote is not None:
        # if the optional tunnel attribute is present, get that
        # tunnel's bindings
        tunnel = CONFTUN.gettunnel(remote)
        if tunnel is None:
            return generror(reply, 'ERROR: IPv6 address not found')
        msg = etree.SubElement(reply, 'conf')
        tunnel.toxml(msg)
    else:
        # else get the whole binding table
        msg = etree.SubElement(reply, 'conf')
        CONFTUN.toxml(msg)

def rpc_flush(reply):
    """ parse <flush> element """
    # remove all nat and tunnel entries from the config file
    CONFFILE.get().truncate()
    CONFNAT.clear()
    CONFTUN.clear()
    resp = AFTRSOCK.get().askreboot()
    if resp != 'OK':
        return generror(reply, 'reboot failure: ' + resp)
    genok(reply)
    return False	# don't need to rewrite config file again

def debug_consistency():
    """consistency check, for debugging"""
    for key, value in CONFTUN.iteritems():
        if key is not value.remote:
            print 'CONFTUN: key', key, 'value', value.remote
        for entry in value.entries:
            xchk = CONFNAT.get((value.remote, entry.saddr,
                                entry.sport, entry.protocol))
            if xchk is None:
                print 'hashkey_src: not found:', \
                    value.remote, entry.saddr, \
                    entry.sport, entry.protocol
            elif xchk is not entry:
                print 'hashkey_src: match error:'
                xchk.totext(sys.stdout)
                entry.totext(sys.stdout)
            xchk = CONFNAT.get((value.addr, entry.nport, entry.protocol))
            if xchk is None:
                print 'hashkey_nat: not found:', \
                    value.addr, entry.nport, entry.protocol
            elif xchk is not entry:
                print 'hashkey_nat: match error:'
                xchk.totext(sys.stdout)
                entry.totext(sys.stdout)
    for key, value in CONFNAT.iteritems():
        if len(key) == 4:
            # source key
            keystr = key[0] + ',' + key[1] + ',' + key[2] + ',' + key[3]
            tunnel = value.parent
            for entry in tunnel.entries:
                if entry is value:
                    break
            if entry is not value:
                print 'tunnel: not found:', keystr
            xchk = CONFNAT.get(value.hashkey_nat())
            if xchk is None:
                print 'hashkey_nat: not found:', keystr
            elif xchk is not value:
                print 'hashkey_nat: match error:', keystr
        else:
            # nat key
            keystr = key[0] + ',' + key[1] + ',' + key[2]
            tunnel = value.parent
            for entry in tunnel.entries:
                if entry is value:
                    break
            if entry is not value:
                print 'tunnel: not found:', keystr
            xchk = CONFNAT.get(value.hashkey_src())
            if xchk is None:
                print 'hashkey_src: not found:', keystr
            elif xchk is not value:
                print 'hashkey_src: match error:', keystr

################ AFTR control connection ################

def debug(msg):
    """debug helper"""
    if VERBOSE.get():
        print msg

AFTRSOCK = MutableGlobal()

class AftrSock:
    """open a control connection to the running aftr"""

    def __init__(self):
        """ initializer """
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM,
                                  socket.IPPROTO_TCP)
        try:
            self.sock.connect(('127.0.0.1', 1015))
        except socket.error as err:
            print 'ERROR:', err[1]
            raise
        self.sock.sendall('session log off\n')
        self.sock.sendall('session config on\n')
        self.sock.sendall('session name aftrconf\n')
        self.transid = 0
        self.nextlinebuf = ''

    def ask(self, cmd):
        """ask aftr something"""
        self.sock.sendall(cmd + '\n')
        debug('sent to AFTR: %s' % cmd)

    def getnextline(self):
        """get next line from AFTR daemon"""
        if len(self.nextlinebuf) == 0:
            self.nextlinebuf = self.sock.recv(1024)
        if not '\n' in self.nextlinebuf:
            ret = self.nextlinebuf
            self.nextlinebuf = ''
            return ret
        i = self.nextlinebuf.index('\n') + 1
        ret = self.nextlinebuf[:i]
        self.nextlinebuf = self.nextlinebuf[i:]
        if ret[-1:] == '\n':
            ret = ret[:-1]
        debug('received from AFTR: %s' % ret)
        return ret

    def expect(self, text):
        """expect a text from AFTR daemon"""
        self.transid += 1
        echo = 'echo ' + str(self.transid)
        try:
            self.sock.sendall(echo + '\n')
        except socket.error as err:
            return (False, err[1])
        i = 5
        got = ''
        while i != 0:
            i -= 1
            prev = got
            got = self.getnextline()
            if len(got) == 0:
                continue
            if got.startswith(text):
                debug('got expected "%s" from AFTR' % text)
                return (True, got[len(text):])
            if got == 'command failed':
                debug('got failure from AFTR')
                return (False, prev)
            if got == echo:
                debug('got echo from AFTR')
                return (False, '')
        return (False, '')

    def asktunnel(self, tunnel, naddr):
        """ask aftr for tunnel natted address"""
        try:
            self.ask('try tunnel ' + tunnel + ' ' + naddr)
        except socket.error as err:
            return err[1]
        (ret, nsrc) = self.expect('tunnel ' + tunnel + ' ' + naddr)
        if ret:
            return naddr
        try:
            self.ask('try tunnel ' + tunnel)
        except socket.error as err:
            return err[1]
        (ret, nsrc) = self.expect('tunnel ' + tunnel + ' ')
        if ret:
            debug('tunnel %s %s' % (tunnel, nsrc))
        else:
            debug('tunnel %s failed?' % tunnel)
        return nsrc

    def askdeltunnel(self, tunnel):
        """ask aftr to delete a tunnel"""
        try:
            self.ask('delete tunnel ' + tunnel)
        except socket.error as err:
            return err[1]
        (ret, resp) = self.expect('')
        if ret or (resp == ''):
            return 'OK'
        else:
            return resp

    def askaddnat(self, binding):
        """ask aftr to create static nat binding"""
        text = 'nat ' + binding.tunnel + ' ' + binding.protocol + \
            ' ' + binding.saddr + ' ' + binding.sport + ' '  + \
            binding.naddr + ' '  + binding.nport
        try:
            self.ask('try ' + text)
        except socket.error as err:
            return err[1]
        (ret, _) = self.expect(text)
        return ret

    def askdelnat(self, nat_entry):
        """ask aftr to delete a static nat binding"""
        try:
            self.ask('delete nat ' + nat_entry.parent.remote + ' ' +
                     nat_entry.protocol + ' ' + nat_entry.saddr +
                     ' ' + nat_entry.sport)
        except socket.error as err:
            return err[1]
        (ret, resp) = self.expect('')
        if ret or (resp == ''):
            return 'OK'
        else:
            return resp

    def askreload(self):
        """ask aftr to reload config file"""
        try:
            self.ask('reload')
        except socket.error as err:
            return err[1]
        # allow the aftr to start the reload before sending the next command
        # (avoid putting 'echo' in the same command buffer)
        time.sleep(1)
        self.transid += 1
        echo = 'echo ' + str(self.transid)
        try:
            self.sock.sendall(echo + '\n')
        except socket.error as err:
            return err[1]
        # block for the first line of the response
        response = self.sock.recv(1024)
        # read until we get the echo
        while echo not in response:
            response += self.sock.recv(1024)
        debug('askreload: got \'' + response + '\'')
        if 'in progress' in response:
            # transient error, try again
            return self.askreload()
        if 'reload failed' in response:
            # actual error is the line before 'reload failed'
            lines = response.splitlines()
            lines.reverse()
            found = False
            line = 'reload failed'
            for line in lines:
                if found:
                    return line
                elif 'reload failed' in line:
                    found = True
            return line
        return 'OK'

    def askreboot(self):
        """ask aftr to reboot"""
        try:
            self.sock.sendall('reboot\n')
        except socket.error as err:
            return err[1]
        self.sock.close()
        del self
        while True:
            time.sleep(1)
            try:
                AFTRSOCK.set(AftrSock())
                return 'OK'
            except socket.error:
                pass

################ main ################

VERBOSE = MutableGlobal(False)

SOCKPORT = 4146
HTTPPORT = 4148

AUTHPEER = MutableGlobal('')

if TRANSPORT == 'http':
    import BaseHTTPServer
    class HttpHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        """handler class"""

        def do_POST(self):
            """POST handler function"""
            # ACL check
            authpeer = AUTHPEER.get()
            if authpeer and (self.client_address[0] != authpeer):
                self.send_error(403, 'Forbidden')
                return
            length = int(self.headers.getheader('Content-Length'))
            request = self.rfile.read(length)
            reply = rpc_parse(request)
            self.send_response(200)
            self.send_header('Content-type','application/xml')
            self.end_headers()
            self.wfile.write(reply)
            # see if it's time to reload the config file
            CONFFILE.get().reload_busy_timeout()

        def do_GET(self):
            """GET handler function"""
            # just in case
            return self.do_POST()

elif TRANSPORT == 'socket':
    import SocketServer
    class SockHandler(SocketServer.BaseRequestHandler):
        """handler class"""

        def handle(self):
            """handler function"""
            if AUTHPEER.get():
                # ACL check
                peer = self.request.getpeername()
                if peer[0] != AUTHPEER.get():
                    # XXX send error message
                    return
            # Most requests should be under 1k, but we have to be able
            # to accomodate large batched requests. So keep reading until
            # we see the </rpc> end tag. But also build in a timeout so
            # we don't wedge on a malformed request.
            self.request.settimeout(3.0)
            request = self.request.recv(1024)
            while '</rpc>' not in request[len(request) - 10:]:
                try:
                    buf = self.request.recv(1024)
                    request += buf
                except socket.timeout:
                    break
            reply = rpc_parse(request)
            # send an xml header for the hell of it
            self.request.sendall('<?xml version="1.0" encoding="UTF-8"?>\n')
            self.request.sendall(reply)
            # see if it's time to reload the config file
            CONFFILE.get().reload_busy_timeout()

else:	# TRANSPORT == 'debug'
    def handler():
        """read from a file, or pipe from aftrconf-client.py"""
        request = ''
        for line in sys.stdin.readlines():
            request = request + line
            if '</rpc>' in line:
                reply = rpc_parse(request)
                print reply
                request = ''

def main(args):
    """main"""
    laddr = ''
    port = 0
    conf = 'aftr.conf'
    try:
        opts, argv = getopt.getopt(args[1:], 'p:l:r:c:v')
    except getopt.GetoptError:
        print 'usage:', args[0], \
            '[-l listening addr] [-p listening port]', \
            '[-r remote addr] [-c config file] [-v]'
        raise
    for opt, arg in opts:
        if opt == '-p':
            port = int(arg)
            continue
        elif opt == '-l':
            laddr = arg
            continue
        elif opt == '-r':
            AUTHPEER.set(arg)
            continue
        elif opt == '-c':
            conf = arg
            continue
        elif opt == '-v':
            VERBOSE.set(True)
            continue
    if len(argv) != 0:
        print args[0] + ':', 'extra arguments:', argv[0], ', ...'
        sys.exit(1)
    CONFFILE.set(ConfigFile(conf))
    try:
        AFTRSOCK.set(AftrSock())
    except socket.error:
        sys.exit(1)
    if TRANSPORT == 'http':
        if port == 0:
            port = HTTPPORT
        rpcserver = BaseHTTPServer.HTTPServer((laddr, port), HttpHandler)
        rpcserver.timeout = RELOADIDLE
        rpcserver.handle_timeout = CONFFILE.get().reload_idle_timeout
        try:
            # we can't use serve_forever() because it ignores timeout
            while True:
                rpcserver.handle_request()
        except KeyboardInterrupt:
            return
    elif TRANSPORT == 'socket':
        if port == 0:
            port = SOCKPORT
        rpcserver = SocketServer.TCPServer((laddr, port), SockHandler)
        rpcserver.timeout = RELOADIDLE
        rpcserver.handle_timeout = CONFFILE.get().reload_idle_timeout
        try:
            while True:
                rpcserver.handle_request()
        except KeyboardInterrupt:
            return
    else:	# TRANSPORT == 'debug'
        # read one request from a file, or pipe from client.py
        handler()

main(sys.argv)
