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
Search in logs (traces in AFTR terms)

Francis_Dupont@isc.org, June 2010

Usage: -d date [-F format] [-f fudge]
       -a address -p port [-P protocol]
       [-t tempfile] [-k] [-z uncompress] files+

Notes:

the timestamp in the front of records is UTC seconds from Unix epoch
(UTC, not localtime).

the fudge argument is for both clock skew and hold down, its default is
5 seconds.

logs (traces in the documentation) record only allocations, not ends of use,
so possible reuses are part of the result:
 - no trace of use: not found0
 - later use: not found+
 - found with later reuse: found!
 - found without later reuse: found
in doubt, keep (-k) the temporary file (tempfile) and look at it
"""   

__version__ = "$Id: searchlog.py 665 2010-06-25 09:14:35Z fdupont $"


import calendar
import getopt
import os
import subprocess
import sys
import time

def main(args):
    """main"""
    datestr = ''
    date = 0
    fudge = 5
    dateformat = None
    address = ''
    port = -1
    protocol = 'tcp'
    tempfilename = '/tmp/sl' + str(os.getpid())
    keep = False
    cat = 'cat'

    try:
        opts, argv = getopt.getopt(args[1:], 'd:F:f:a:p:P:t:kz:')
    except getopt.GetoptError:
        print 'usage:', args[0], \
            '-d date [-F format] [-f fudge] -a address', \
            '-p port [-P protocol] [-t tempfile] [-k]', \
            '[-z uncompress] files+'
        raise
    for opt, arg in opts:
        if opt == '-d':
            datestr = arg
            continue
        elif opt == '-F':
            dateformat = arg
            continue
        elif opt == '-f':
            fudge = int(arg)
            continue
        elif opt == '-a':
            address = arg
            continue
        elif opt == '-p':
            port = int(arg)
            continue
        elif opt == '-P':
            protocol = arg
            continue
        elif opt == '-t':
            tempfilename = arg
            continue
        elif opt == '-k':
            keep = True
            continue
        elif opt == '-z':
            cat = arg

    if datestr == '':
        print args[0] + ':', '\'-d date\' is required'
        sys.exit(1)
    if dateformat is None:
        try:
            date = calendar.timegm(time.strptime(datestr))
        except ValueError:
            print args[0] + ':', '\'-d date\' illegal value', datestr
            raise
    else:
        try:
            date = calendar.timegm(time.strptime(datestr, dateformat))
        except:
            print args[0] + ':', 'can\'t parse date', datestr, \
                'with format', dateformat
            raise
    if date == 0:
        print args[0] + ':', 'something wrong with date', datestr
        sys.exit(1)
    if fudge <= 0:
        print args[0] + ':', '\'-f fudge\' illegal value', fudge
        sys.exit(1)
    if address == '':
        print args[0] + ':', '\'-a address\' is required'
        sys.exit(1)
    if port == -1:
        print args[0] + ':', '\'-p port\' is required'
        sys.exit(1)
    if (port <= 0) or (port > 65535):
        print args[0] + ':', '\'-p port\' illegal port', port
        sys.exit(1)
    if (protocol != 'tcp') and (protocol != 'udp'):
        print args[0] + ':', '\'-p protocol\' illegal value', protocol
        sys.exit(1)
    if len(argv) == 0:
        print args[0] + ':', 'files+ are required arguments'
        sys.exit(1)

    grep = [cat]
    grep += argv
    grep += ['|', 'grep', '\' ' + address + ' ' + protocol + ' \'']
    grep += ['|', 'grep', '-w', '#' + str(port)]
    grep += ['|', 'sed', '\'s/.*: //\'']
    grep += ['|', 'sort', '-k1', '-n', '-u']
    grep += ['>', tempfilename]
    print ' '.join(grep)
    try:
        subprocess.call(['csh', '-c', ' '.join(grep)])
    except:
        print args[0] + ':', 'system failed for', grep
        raise
    dateminus = date - fudge
    dateplus = date + fudge
    before = ''
    after = ''
    try:
        tempfile = open(tempfilename)
    except:
        print args[0] + ':', 'can\'t open tempfile', tempfilename
        raise
    for line in tempfile.readlines():
        line = line.rstrip()
        items = line.split()
        if len(items) < 6:
            print args[0] + ':', 'bad entry', line
            continue
        if int(items[0]) < dateplus:
            before = items[2]
        elif (after == '') and (int(items[0]) > dateminus):
            after = items[2]
            break
    if not keep:
        os.remove(tempfilename)
    if (before == '') and (after == ''):
        print 'not found0'
    elif before == '':
        print 'not found+'
    elif after == '':
        print 'found!:', before
    else:
        print 'found:', before
    
main(sys.argv)
