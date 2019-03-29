#!/usr/bin/env python
#
# Tool:    
#	dnssecchef.py
#
# Description:
#
#   DNSSECChef is a highly configurable DNS and DNSSEC proxy for penetration testers 
#   (based on DNSChef).
#
#   Please visit https://www.github.com/dinosec/dnssecchef for the latest version 
#   and documentation. Please forward all issues and concerns to raul [at] dinosec.com.
#
#   Tested in macOS and Linux.
#
# URL:     
#   https://github.com/dinosec/dnssecchef
#
# Authors:  
#	Raul Siles (raul _AT_ dinosec _DOT_ com)
#	Monica Salas (monica _AT_ dinosec _DOT_ com)
#	(c) 2019 DinoSec (www.dinosec.com)
#
# Date:		2019-03-21
# Version:	0.5
#
#
# Copyright (C) 2019 DinoSec (Monica Salas & Raul Siles)
# All rights reserved.
#
# - Based on dnschef version 0.3:
# https://github.com/iphelix/dnschef
#
# - Using dnslib version 0.9.10+:
# https://pypi.org/project/dnslib/
# https://bitbucket.org/paulc/dnslib/
# https://github.com/paulchakravarti/dnslib
#
#
# 
# - Pre-requisites, for macOS and Linux:
#
# Python 2.7.x, plus:
#
# $ pip install IPy
# $ pip install dnslib
#
# dnssecchef v0.5+ requires dnslib v0.9.10+.
#
#
# - CHANGES:
#
# v0.5
# [v]- Contributed code to dnslib/dns.py v0.9.8 to add getters/setters for the 
#      DNSSEC flags AD, CD and DO. These are available since dnslib v0.9.10.
#      CD flag remains unused in this dnssecchef version.
# [v]- Changed dnssecchef code to use these DNSSEC flags straight from the library.
# [v]- Implemented the logic for three DNSSEC behaviours or policies (defined below): 
#      default, --dnssec & --nodnssec.
#
#
# v0.4 (never published)
# [v]- Name changed to DNSSECChef (from DNSChef).
# [v]- Default support for UDP and TCP, plus new individual options (-u and -t) to
#      enable UDP or TCP only mode, individually.
# [v]- Capabilities to replicate the protocol used by the client when proxying
#      requests: UDP or TCP.
# [v]- New "--dnssec" option to play with the DNSSEC flags/bits in queries and
#      responses. Pending: Add the logic for multiple manipulations and attacks.
#
#
# - TODO:
# [-]- Add support for DS (and other DNSSEC) records.
# [-]- Add support for NSEC records (available in dnslib v0.9.10).
# [-]- Enable new manipulation options with the DNSSEC CD flag.
#
#
# - DOCs:
# https://docs.python.org/2/library/socketserver.html
# 
#
#
#
# Copyright (C) 2019 DinoSec (www.dinosec.com) - Monica Salas & Raul Siles
# All rights reserved.
#
# ---------------------------------------------
# https://opensource.org/licenses/BSD-3-Clause
# ---------------------------------------------
#
# - Previous author Copyright:
#
# DNSChef is a highly configurable DNS Proxy for Penetration Testers 
# and Malware Analysts. Please visit http://thesprawl.org/projects/dnschef/
# for the latest version and documentation. Please forward all issues and
# concerns to iphelix [at] thesprawl.org.
#
# DNSCHEF_VERSION = "0.3"
#
# Copyright (C) 2014 Peter Kacherginsky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ---------------------------------------------
#
#
#
#
# - Default dnssecchef DNSSEC manipulation options: 
#   (DNSSEC flag policy for options 1 and 2)
#   (Search for label POLICY in the source code)
#
#   OPTION 1
#   1.- DNS queries that will be proxied, with no local manipulation.
#       (Search for label 'PROXY' in the source code)
#       Message: "proxying a request of ..."
#
#       By default:
#           Leave the DO and AD flags from the request in the DNS forwarded query. 
#           Do nothing, that is, leave everything as it is ;-)
#           Do not change the response received either.
#
#       If --dnssec is set:
#           If the DO flag is set, set both the DO and the AD flags in the response.
#           If the AD flag is set (but DO is not), set only the AD flag in the response.
#           If none of the flags are set, do NOT set the AD flag in the response.
#
#       If --nodnssec is set:
#           Remove both the DO and the AD flags for the DNS forwarded query and (as a
#           result, from the response received).
#
#   OPTION 2
#   2.- DNS queries that will be cooked, based in the local manipulation options. 
#       Message: "cooking the response of ..."
#
#       By default:
#           Reflect the DO and AD flags from the request in the response. 
#           Do nothing, that is, leave everything as it is ;-)
#
#       If --dnssec is set:
#           If the AD flag is set, set the AD flag in the response.
#           If the DO flag is set, set both the DO and the AD flags in the response.
#           If none of the flags are set, set the AD flag in the response (too).
#
#       If --nodnssec is set:
#           Remove both the DO and the AD flags both for the forwarded query and (as a
#           result, from the response received).
#
#   OPTION 3 (no policy)
#   3.- Do not change direct DNS responses received by the tool (is focused in queries).
#       Search for label 'RESPONSE' in the source code.
#
#

# Search PATH for modules: PYTHONPATH
#sys.path.append("/usr/share/dnschef/")

import sys

from optparse import OptionParser,OptionGroup
from ConfigParser import ConfigParser

from dnslib import *
from IPy import IP

import threading, random, operator, time
import SocketServer, socket, os
import binascii
import string
import base64
import time

# Version
DNSSECCHEF_VERSION = "0.5"

# EDNS0 length
EDNS0_LENGTH=4096

# DNS UDP and TCP receive buffer size
BUFFSIZE=4096

# Enable DNSSEC manipulations (disabled by default)
dnssec=0

# Disable DNSSEC completely (disabled by default)
nodnssec=0

# Verbosity
verbose=0


#
# DNSHandler Mixin. The class contains generic functions to parse DNS requests and
# calculate an appropriate response based on user parameters.
#
# Provide the transport protocol to proxy requests using the same protocol: UDP or TCP.
#
class DNSHandler():

    #
    # ----
    #    
    # - AD,CD and DO bit parsing code contributed to dnslib/dns.py (v0.9.10+):
    #
    # DNS AD and CD flags:
    # URL: https://tools.ietf.org/html/rfc2065#section-6.1
    #
    # 6.1 The AD and CD Header Bits
    # 
    #                                      1  1  1  1  1  1
    #        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |                      ID                       |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |                    QDCOUNT                    |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |                    ANCOUNT                    |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |                    NSCOUNT                    |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #      |                    ARCOUNT                    |
    #      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #
    # ----
    #
    # DNS (EDNS0) DO flag:
    # https://tools.ietf.org/html/rfc6891#section-6.1.3
    #
    # 6.1.3.  OPT Record TTL Field Use
    #
    #                    +0 (MSB)                            +1 (LSB)
    #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    # 0: |         EXTENDED-RCODE        |            VERSION            |
    #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    # 2: | DO|                           Z                               |
    #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    #
    # ----
    #
    
    def printflags(self,do,ad):
        flags=""
        if do and ad:
            flags = "DO AD"
        elif do:
            flags = "DO"
        elif ad:
            flags = "AD"
        #else
        #    flags = ""
        return flags
    
    # Getting the DO flag 'data' is a DNSRecord (we parse the data.ar).
    def getDO(self, data):
        for rr in data.ar:
            if rr.rtype == QTYPE.OPT:
                return rr.get_do()
    
    # Setting the DO flag 'data' is a DNSRecord (we parse the data.ar) and
    # return data again.
    def setDO(self, data, value):
        # Is there an OPT (type) AR (Additional Record) in the DNSRecord?
        existopt=False
        for rr in data.ar:
            if rr.rtype == QTYPE.OPT:
                existopt=True
                rr.set_do(value)
        # If there is no OPT AR in the DNSRecord, and the DO flag must be set, 
        # add the EDNS0 OPT RR manually
        if value and not existopt: # The DO flag is set
            if verbose:
                print "[DEBUG] Adding a new OPT record with the DO flag set..."
            opt = EDNS0(flags="do",udp_len=EDNS0_LENGTH,version=0)
            data.add_ar(opt)
        return data
        
    # Getting the AD flag 'data' is a DNSRecord (we parse the data.header).
    def getAD(self, data):
        return data.header.get_ad()
    
    # Setting the AD flag 'data' is a DNSRecord (we parse the data.header) and
    # return just the header.
    def setAD(self, data, value):
        newheader=data.header
        newheader.set_ad(value)
        return newheader
    
    # Parse DNS protocol data as DNSRecord(s)
    def parse(self,data,proxyprotocol):
        response = ""
        req_ad=0
        req_do=0
        resp_ad=0
        resp_do=0
        #ad=0
        #do=0
        
        try:
            # Parse data as DNS
            d = DNSRecord.parse(data)
            #if verbose:
                #print "[DEBUG]"
                #print d
                #print d.header.bitmap
        
            # DNSRecord: DNSHeader and DNSQuestion and/or RR
            #     q - Question Section
            #     a - Answer Section
            #     auth - Authority Section
            #     ar - Additional (Records) Section
            
        except Exception, e:
            print "[%s] %s: ERROR: %s" % (time.strftime("%H:%M:%S"), self.client_address[0], "invalid DNS request")
            #print e
            if self.server.log: self.server.log.write( "[%s] %s: ERROR: %s\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], "invalid DNS request") )

        else:        
            # Only Process DNS Queries
            if QR[d.header.qr] == "QUERY":

                qtype = QTYPE[d.q.qtype]
                
                # Gather query parameters
                # NOTE: Do not lowercase qname here, because we want to see
                #       any case request weirdness in the logs.
                qname = str(d.q.qname)
                
                # DNSSEC
                # Get DNSSEC flags from request (QUERY)
                req_ad = self.getAD(d)
                req_do = self.getDO(d)

                #if verbose:
                    #print "[DEBUG] qtype= %s, qname: %s (%s)" % (qtype, qname, self.printflags(req_do,req_ad))
                
                #
                # This is the default DNSSEC flag policy. If a different manipulation is
                # desired for proxied queries, change the proxy policy (it is used instead
                # of this policy; search for PROXY in the source code).
                #
                # DNSSEC (flag policy .- OPTION 2)
                # POLICY
                # 
                if dnssec:
                    if req_do:
                        resp_do = 1
                        resp_ad = 1
                    elif req_ad:
                        resp_ad = 1
                    else:
                        resp_ad = 1
                elif nodnssec:
                    resp_do = 0
                    resp_ad = 0
                else:
                    resp_do = req_do
                    resp_ad = req_ad
                
                #if verbose:
                    #print "[DEBUG] qtype= %s, qname: %s (%s) --> (%s)" % (qtype, qname, self.printflags(req_do,req_ad), self.printflags(resp_do,resp_ad))
                                
                # Chop off the last period
                if qname[-1] == '.': qname = qname[:-1]
                
                # Query details: https://bitbucket.org/paulc/dnslib/ - Source: /dnslib/dns.py
                
                # Find all matching fake DNS records for the query name or get False
                fake_records = dict()

                for record in self.server.nametodns:

                    fake_records[record] = self.findnametodns(qname,self.server.nametodns[record])
                
                # Check if there is a fake record for the current request qtype
                if qtype in fake_records and fake_records[qtype]:

                    fake_record = fake_records[qtype]

                    # DNSSEC: AD
                    newheader=self.setAD(d, resp_ad)
                    newbitmap=newheader.bitmap
                    
                    # Create a custom response to the query
                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=newbitmap, qr=1, aa=1, ra=1), q=d.q)

                    # DNSSEC: DO
                    self.setDO(response, resp_do)
                                        
                    print "[%s] %s: cooking the response of type '%s' for %s (%s) to %s (%s)" % (time.strftime("%H:%M:%S"), self.client_address[0], qtype, qname, self.printflags(req_do,req_ad), fake_record, self.printflags(resp_do,resp_ad))
                    if self.server.log: self.server.log.write( "[%s] %s: cooking the response of type '%s' for %s (%s) to %s (%s)\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], qtype, qname, self.printflags(req_do,req_ad), fake_record, self.printflags(resp_do,resp_ad)) )

                    # IPv6 needs additional work before inclusion:
                    if qtype == "AAAA":
                        ipv6 = IP(fake_record)
                        ipv6_bin = ipv6.strBin()
                        ipv6_hex_tuple = [int(ipv6_bin[i:i+8],2) for i in xrange(0,len(ipv6_bin),8)]
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](ipv6_hex_tuple)))

                    elif qtype == "SOA":
                        mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                        times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                        # dnslib doesn't like trailing dots
                        if mname[-1] == ".": mname = mname[:-1]
                        if rname[-1] == ".": rname = rname[:-1]

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                    elif qtype == "NAPTR":
                        order,preference,flags,service,regexp,replacement = fake_record.split(" ")
                        order = int(order)
                        preference = int(preference)

                        # dnslib doesn't like trailing dots
                        if replacement[-1] == ".": replacement = replacement[:-1]

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,DNSLabel(replacement))) )

                    elif qtype == "SRV":
                        priority, weight, port, target = fake_record.split(" ")
                        priority = int(priority)
                        weight = int(weight)
                        port = int(port)
                        if target[-1] == ".": target = target[:-1]

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                    elif qtype == "DNSKEY":
                        flags, protocol, algorithm, key = fake_record.split(" ")
                        flags = int(flags)
                        protocol = int(protocol)
                        algorithm = int(algorithm)
                        key = base64.b64decode(("".join(key)).encode('ascii'))

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                    elif qtype == "RRSIG":
                        covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                        covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                        algorithm = int(algorithm)
                        labels = int(labels)
                        orig_ttl = int(orig_ttl)
                        sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                        sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                        key_tag = int(key_tag)
                        if name[-1] == '.': name = name[:-1]
                        sig = base64.b64decode(("".join(sig)).encode('ascii'))

                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig) ))
                        
                    #elif qtype == "DS":
                        # TODO
                    #
                    else:
                        # dnslib doesn't like trailing dots
                        if fake_record[-1] == ".": fake_record = fake_record[:-1]
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                    response = response.pack()                   

                elif qtype == "*" and not None in fake_records.values():
                    
                    # DNSSEC: AD
                    newheader=self.setAD(d, resp_ad)
                    newbitmap=newheader.bitmap
                    
                    # Create a custom response to the query
                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=newbitmap,qr=1, aa=1, ra=1), q=d.q)
                    
                    # DNSSEC: DO
                    self.setDO(response, resp_do)
                                        
                    print "[%s] %s: cooking the response of type '%s' for %s (%s) with %s (%s)" % (time.strftime("%H:%M:%S"), self.client_address[0], "ANY", qname, self.printflags(req_do,req_ad), "all known fake records.", self.printflags(resp_do,resp_ad))
                    if self.server.log: self.server.log.write( "[%s] %s: cooking the response of type '%s' for %s (%s) with %s (%s)\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], "ANY", qname, self.printflags(req_do,req_ad), "all known fake records.", self.printflags(resp_do,resp_ad)) )

                    for qtype,fake_record in fake_records.items():
                        if fake_record:

                            # NOTE: RDMAP is a dictionary map of qtype strings to handling classses
                            # IPv6 needs additional work before inclusion:
                            if qtype == "AAAA":
                                ipv6 = IP(fake_record)
                                ipv6_bin = ipv6.strBin()
                                fake_record = [int(ipv6_bin[i:i+8],2) for i in xrange(0,len(ipv6_bin),8)]

                            elif qtype == "SOA":
                                mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                                times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                                # dnslib doesn't like trailing dots
                                if mname[-1] == ".": mname = mname[:-1]
                                if rname[-1] == ".": rname = rname[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                            elif qtype == "NAPTR":
                                order,preference,flags,service,regexp,replacement = fake_record.split(" ")
                                order = int(order)
                                preference = int(preference)

                                # dnslib doesn't like trailing dots
                                if replacement and replacement[-1] == ".": replacement = replacement[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,replacement)))

                            elif qtype == "SRV":
                                priority, weight, port, target = fake_record.split(" ")
                                priority = int(priority)
                                weight = int(weight)
                                port = int(port)
                                if target[-1] == ".": target = target[:-1]

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                            elif qtype == "DNSKEY":
                                flags, protocol, algorithm, key = fake_record.split(" ")
                                flags = int(flags)
                                protocol = int(protocol)
                                algorithm = int(algorithm)
                                key = base64.b64decode(("".join(key)).encode('ascii'))

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                            elif qtype == "RRSIG":
                                covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                                covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                                algorithm = int(algorithm)
                                labels = int(labels)
                                orig_ttl = int(orig_ttl)
                                sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                                sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                                key_tag = int(key_tag)
                                if name[-1] == '.': name = name[:-1]
                                sig = base64.b64decode(("".join(sig)).encode('ascii'))

                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig) ))
                                
                            #elif qtype == "DS":
                                # TODO
                            #
                            else:
                                # dnslib doesn't like trailing dots
                                if fake_record[-1] == ".": fake_record = fake_record[:-1]
                                response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                    response = response.pack()

                #
                # PROXY
                #
                # Simply proxy the request:
                # qtype is not in fake records (file or command line parameters).
                # No need to perform local modifications or cooking...
                #
                else:
                    # Fix root (.) qnames in logs
                    if qname == "": qname = "."
                    
                    # DNSSEC (flag policy .- OPTION 1)
                    # POLICY
                    # 
                    if dnssec:
                        if req_do:
                            resp_do = 1
                            resp_ad = 1
                        elif req_ad:
                            resp_ad = 1
                        else:
                            resp_ad = 0
                    elif nodnssec:
                        resp_do = 0
                        resp_ad = 0
                    else:
                        resp_do = req_do
                        resp_ad = req_ad
                    
                    print "[%s] %s: proxying a request of type '%s' for %s (%s) --> (%s)" % (time.strftime("%H:%M:%S"), self.client_address[0], qtype, qname, self.printflags(req_do,req_ad), self.printflags(resp_do,resp_ad))
                    if self.server.log: self.server.log.write( "[%s] %s: proxying a request of type '%s' for %s (%s) --> (%s)\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], qtype, qname, self.printflags(req_do,req_ad), self.printflags(resp_do,resp_ad)) )

                    nameserver_tuple = random.choice(self.server.nameservers).split('#')
                    
                    #if verbose:
                        #print "[DEBUG] Nameserver(s): %s" % nameserver_tuple
                    #
                    # E.g. Nameserver(s): ['8.8.8.8']
                    #
                    # Add the RD (Recursion Desired) bit to the proxied queries:
                    # Required when the requester is a DNS resolver iterating through DNS auth. servers
                    #
                    new_query = DNSRecord.parse(data)
                    #if verbose:
                        #print "[DEBUG] New DNS query to forward upstream:\n%s" % new_query
                    
                    # DNSSEC
                    # Change the DNSSEC flags in the DNS forwarded query...
                    # (based on the DNSSEC flag policy above)               
                    new_query_do = self.setDO(new_query,resp_do)
                    new_header = self.setAD(new_query_do,resp_ad)
                    new_header.set_rd(1)
                    new_data = new_query_do.pack()
                                        
                    #response = self.proxyrequest(data,proxyprotocol,*nameserver_tuple)
                    response = self.proxyrequest(new_data,proxyprotocol,*nameserver_tuple)
                    
                    # DNSSEC
                    # Change DNSSEC flags in the DNS proxied response...
                    # 
                    # As the DNSSEC flags were already changed in the DNS forwarded query,
                    # for example, when 'nodnssec' is set, the proxy should never receive 
                    # a DNSSEC response (both DO and AD flags have been unset in the query).
                    #
                    # response is a string, not a DNSRecord.
                    #
                                
            #
            # RESPONSE
            #
            # Only process DNS Queries: Simply output when a DNS response is received
            #
            elif QR[d.header.qr] == "RESPONSE":
                qtype = QTYPE[d.q.qtype]
                qname = str(d.q.qname)
                                    
                # DNSSEC
                # Get the DNSSEC flags from the response received (RESPONSE)
                resp_ad = self.getAD(self,d)
                resp_do = self.getDO(self,d)

                #if verbose:
                    #print "[DEBUG] Response qtype= %s, qname: %s (%s)" % (qtype, qname, self.printflags(resp_do,resp_ad))

                print "[%s] %s: processing a DNS response of type '%s' for %s (%s)" % (time.strftime("%H:%M:%S"), self.client_address[0], qtype, qname, self.printflags(resp_do,resp_ad))
                if self.server.log: self.server.log.write( "[%s] %s: processing a DNS response of type '%s' for %s (%s)\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], qtype, qname, self.printflags(resp_do,resp_ad)) )
                
        return response         
    

    # Find appropriate IP address to use for a queried name 
    def findnametodns(self,qname,nametodns):

        # Make qname case insensitive
        qname = qname.lower()
    
        # Split and reverse qname into components for matching.
        qnamelist = qname.split('.')
        qnamelist.reverse()
    
        # HACK: It is important to search the nametodns dictionary before iterating it so that
        # global matching ['*.*.*.*.*.*.*.*.*.*'] will match last. Use sorting for that.
        for domain,host in sorted(nametodns.iteritems(), key=operator.itemgetter(1)):

            # NOTE: It is assumed that domain name was already lowercased
            #       when it was loaded through --file, --fakedomains or --truedomains
            #       don't want to waste time lowercasing domains on every request.

            # Split and reverse domain into components for matching
            domain = domain.split('.')
            domain.reverse()
            
            # Compare domains in reverse.
            for a,b in map(None,qnamelist,domain):
                if a != b and b != "*":
                    break
            else:
                # Could be a real IP or False if we are doing reverse matching with 'truedomains'
                return host
        else:
            return False
    
    #
    # Obtain a response from a real DNS server.
    #
    # Proxy the request using the same transport protocol used in the original query:
    # UDP or TCP.
    #
    def proxyrequest(self, request, protocol, host, port="53"):
        #if verbose:
            #print "[DEBUG] Request:\n%s" % DNSRecord.parse(request)
            #print "[DEBUG] Host:     %s" % host
            #print "[DEBUG] Port:     %s" % port
            #print "[DEBUG] Protocol: %s" % protocol
        reply = None
        try:
            if self.server.ipv6:

                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

            else:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(3.0)

            # Send the proxy request to a randomly chosen DNS server
            if protocol == "udp":
                sock.sendto(request, (host, int(port)))
                reply = sock.recv(BUFFSIZE)
                sock.close()

            elif protocol == "tcp":
                sock.connect((host, int(port)))

                # Add length for the TCP request
                length = binascii.unhexlify("%04x" % len(request)) 
                sock.sendall(length+request)

                # Strip length from the response
                reply = sock.recv(BUFFSIZE)
                reply = reply[2:]

                sock.close()

        except Exception, e:
            print "[!] Could not proxy request: %s" % e
        else:
            return reply 

# UDP DNS Handler for incoming requests
class UDPHandler(DNSHandler, SocketServer.BaseRequestHandler):

    def handle(self):
        (data,socket) = self.request
        response = self.parse(data,"udp")
        
        if response:
            socket.sendto(response, self.client_address)

# TCP DNS Handler for incoming requests       
class TCPHandler(DNSHandler, SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(BUFFSIZE)
        
        # Remove the additional "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data,"tcp")
        
        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol 
            length = binascii.unhexlify("%04x" % len(response))            
            self.request.sendall(length+response)            

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):

    # Override SocketServer.UDPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns  = nametodns
        self.nameservers = nameservers
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass) 

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    
    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns   = nametodns
        self.nameservers = nameservers
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        SocketServer.TCPServer.__init__(self,server_address,RequestHandlerClass) 
        
# Initialize and start the DNS Server        
def start_cooking(interface, nametodns, nameservers, udp=False, tcp=False, ipv6=False, port="53", logfile=None):
    try:

        if logfile is not None: 
            log = open(logfile,'a',0)
            log.write("[%s] DNSSECChef is active.\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z")) )
        else:
            log = None
        
        # By default the proxy runs in both DNS ports, UDP 53 and TCP 53
        # If the --udp or --tcp options are specified, it runs only in that protocol mode
        
        # If none of these options are specified through the options, then set both by default
        if not udp and not tcp:
            udp = True
            tcp = True
        elif udp and tcp:
            print "[!] DNSSECChef runs by default in UDP and TCP modes. Do not set both..."
            server_udp = server_tcp = None
            sys.exit()
        
        if udp and tcp:
            print "[*] DNSSECChef is running in both UDP and TCP modes (default)"        
            server_udp = ThreadedUDPServer((interface, int(port)), UDPHandler, nametodns, nameservers, ipv6, log)
            server_tcp = ThreadedTCPServer((interface, int(port)), TCPHandler, nametodns, nameservers, ipv6, log)
        elif udp:
            print "[*] DNSSECChef is running in UDP only mode"
            server_udp = ThreadedUDPServer((interface, int(port)), UDPHandler, nametodns, nameservers, ipv6, log)            
        elif tcp:
            print "[*] DNSSECChef is running in TCP only mode"
            server_tcp = ThreadedTCPServer((interface, int(port)), TCPHandler, nametodns, nameservers, ipv6, log)
        
        print "[*] ...\n"
        
        # Start a thread with the server -- that thread will then start
        # more threads for each request
        if udp:
            thread_server_udp = threading.Thread(target=server_udp.serve_forever)
        if tcp:
            thread_server_tcp = threading.Thread(target=server_tcp.serve_forever)
        
        # Exit the server thread when the main thread terminates
        if udp:
            thread_server_udp.daemon = True
            thread_server_udp.start()
        if tcp:
            thread_server_tcp.daemon = True
            thread_server_tcp.start()
        
        # Loop in the main thread
        while True: time.sleep(100)

    except (KeyboardInterrupt, SystemExit):

        if log:
            log.write("[%s] DNSSECChef is shutting down.\n" % (time.strftime("%d/%b/%Y:%H:%M:%S %z")) )
            log.close()
        if udp and server_udp is not None:
            server_udp.shutdown()
        if tcp and server_tcp is not None:
            server_tcp.shutdown()
        print "\n[*] DNSSECChef is shutting down."
        sys.exit()

    except IOError, e:
        # [Errno 13] Permission denied
        if e.errno == 13:
            print "[!] Permission denied: Run DNSSECChef as root."
        elif e.errno == 98:
            print "[!] Address already in use: Release all DNS ports (53/udp, 53/tcp)."
        else:
            print "[!] Failed to open log file (%s) for writing." % logfile
        #print "[!] Exception: %s" % e

    except Exception, e:
        print "[!] Failed to start the server: %s" % e


if __name__ == "__main__":

    header  = "          _                               _          __  \n"
    header += "         | | version %s                 | |        / _| \n" % DNSSECCHEF_VERSION
    header += "       __| |_ __  ___  ___  ___  ___  ___| |__   ___| |_ \n"
    header += "      / _` | '_ \/ __|/ __|/ _ \/ __|/ __| '_ \ / _ \  _|\n"
    header += "     | (_| | | | \__ \\\__ \  __/ (__| (__| | | |  __/ |  \n"
    header += "      \__,_|_| |_|___/|___/\___|\___|\___|_| |_|\___|_|  \n"
    header += "                                                         \n"
    header += "       (c) 2019 DinoSec                                  \n"
    header += "           monica@dinosec.com & raul@dinosec.com         \n"

    # Parse command line arguments
    parser = OptionParser(usage = "dnssecchef [options]:\n" + header, description="DNSSECChef is a highly configurable DNS Proxy for Penetration Testers with additional DNSSEC capabilities (based on DNSChef). It is capable of fine configuration of which DNS replies to modify or to simply proxy with real responses. In order to take advantage of the tool you must either manually configure or poison DNS server entry to point to DNSSECChef, or use it as a transparent proxy. The tool requires root privileges to run on privileged ports." )
    
    fakegroup = OptionGroup(parser, "Fake DNS records")
    fakegroup.add_option('--fakeip', metavar="192.0.2.1", action="store", help='IP address to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'A\' queries will be spoofed. Consider using --file argument if you need to define more than one IP address.')
    fakegroup.add_option('--fakeipv6', metavar="2001:db8::1", action="store", help='IPv6 address to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'AAAA\' queries will be spoofed. Consider using --file argument if you need to define more than one IPv6 address.')
    fakegroup.add_option('--fakemail', metavar="mail.fake.com", action="store", help='MX name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'MX\' queries will be spoofed. Consider using --file argument if you need to define more than one MX record.')
    fakegroup.add_option('--fakealias', metavar="www.fake.com", action="store", help='CNAME name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'CNAME\' queries will be spoofed. Consider using --file argument if you need to define more than one CNAME record.')
    fakegroup.add_option('--fakens', metavar="ns.fake.com", action="store", help='NS name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'NS\' queries will be spoofed. Consider using --file argument if you need to define more than one NS record.')
    fakegroup.add_option('--file', action="store", help="Specify a file containing a list of DOMAIN=IP pairs (one pair per line) used for DNS responses. For example: google.com=10.10.10.10 will force all queries to 'google.com' to be resolved to '10.10.10.10'. IPv6 addresses will be automatically detected. You can be even more specific by combining --file with other arguments. However, data obtained from the file (e.g. dnssecchef.ini) will take precedence over others.")
    parser.add_option_group(fakegroup)

    parser.add_option('--fakedomains', metavar="dinosec.com,google.com", action="store", help='A comma separated list of domain names which will be resolved to FAKE values specified in the the parameters below. All other domain names will be resolved to their true values.')
    parser.add_option('--truedomains', metavar="dinosec.com,google.com", action="store", help='A comma separated list of domain names which will be resolved to their true values. All other domain names will be resolved to fake values specified in the parameters below.')
    
    rungroup = OptionGroup(parser,"Optional runtime parameters")
    rungroup.add_option("--logfile", action="store", help="Specify a log file to record all activity")
    rungroup.add_option("--nameservers", metavar="8.8.8.8#53 or 4.2.2.1#53#tcp or 2001:4860:4860::8888", default='8.8.8.8', action="store", help='A comma separated list of alternative DNS servers to use with proxied requests. Nameservers can have either IP or IP#PORT format. A randomly selected server from the list will be used for proxy requests when provided with multiple servers. By default, the tool uses Google\'s public DNS server 8.8.8.8 when running in IPv4 mode and 2001:4860:4860::8888 when running in IPv6 mode.')
    rungroup.add_option("-i","--interface", metavar="127.0.0.1 or ::1", default="127.0.0.1", action="store", help='Define an interface to use for the DNS listener. By default, the tool uses 127.0.0.1 for IPv4 mode and ::1 for IPv6 mode.')
    rungroup.add_option("-d","--dnssec", action="store_true", default=False, help="Enable DNSSEC flags manipulation in DNS queries and responses (disabled by default).")
    rungroup.add_option("-n","--nodnssec", action="store_true", default=False, help="Completely remove support for DNSSEC in the tool, use plain DNS (disabled by default).")    
    rungroup.add_option("-u","--udp", action="store_true", default=False, help="Run in UDP only mode, instead of the default UDP and TCP mode.")
    rungroup.add_option("-t","--tcp", action="store_true", default=False, help="Run in TCP only mode, instead of the default UDP and TCP mode.")
    rungroup.add_option("-6","--ipv6", action="store_true", default=False, help="Run in IPv6 mode.")
    rungroup.add_option("-p","--port", action="store", metavar="53", default="53", help='Port number to listen for DNS requests.')
    rungroup.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Verbose messages.")
    rungroup.add_option("-q", "--quiet", action="store_false", dest="headers", default=True, help="Don't show headers.")
    parser.add_option_group(rungroup)
    
    (options,args) = parser.parse_args()

    # Verbosity
    if options.verbose:
        verbose=1
         
    # Print program header
    if options.headers:
        print header
    
    # Main storage of domain filters
    # NOTE: RDMAP is a dictionary map of qtype strings to handling classes
    nametodns = dict()
    for qtype in RDMAP.keys():
        nametodns[qtype] = dict()
    
    # Incorrect or incomplete command line arguments
    if options.fakedomains and options.truedomains:
        print "[!] You can not specify both 'fakedomains' and 'truedomains' parameters."
        sys.exit(0)
        
    elif not (options.fakeip or options.fakeipv6) and (options.fakedomains or options.truedomains):
        print "[!] You have forgotten to specify which IP to use for fake responses"
        sys.exit(0)

    # Notify user about alternative listening port
    if options.port != "53":
        print "[*] Listening on an alternative port %s" % options.port

    # Adjust defaults for IPv6
    if options.ipv6:
        print "[*] Using IPv6 mode."
        if options.interface == "127.0.0.1":
            options.interface = "::1"

        if options.nameservers == "8.8.8.8":
            options.nameservers = "2001:4860:4860::8888"

    print "[*] DNSSECChef started on interface: %s" % options.interface
    
    # Use alternative DNS servers
    if options.nameservers:
        nameservers = options.nameservers.split(',')
        print "[*] Using the following nameservers: %s" % ", ".join(nameservers)

    # DNSSEC options:
    if options.dnssec and options.nodnssec:
        print "[!] The --dnssec and --nodnssec options cannot be used simultaneously"
        sys.exit(0)
    # No DNSSEC option enabled
    elif options.nodnssec:
        nodnssec = 1
        dnssec = 0
        print "[>] Disabling DNSSEC support completely..."
    # DNSSEC option enabled
    elif options.dnssec:
        nodnssec = 0
        dnssec = 1
        print "[>] Enabling DNSSEC flags manipulations..."

    # External file definitions
    if options.file:
        print "[*] --- file ---"
        config = ConfigParser()
        config.read(options.file)
        for section in config.sections():

            if section in nametodns:
                for domain,record in config.items(section):

                    # Make domain case insensitive
                    domain = domain.lower()

                    nametodns[section][domain] = record
                    print "[+] Cooking %s replies for domain %s with '%s'" % (section,domain,record)
            else:
                print "[!] DNS Record '%s' is not supported. Ignoring section contents." % section
        print "[*] --- "
            
    # DNS Record and Domain Name definitions
    # NOTE: '*.*.*.*.*.*.*.*.*.*' domain is used to match all possible queries.
    if options.fakeip or options.fakeipv6 or options.fakemail or options.fakealias or options.fakens:
        fakeip     = options.fakeip
        fakeipv6   = options.fakeipv6
        fakemail   = options.fakemail
        fakealias  = options.fakealias
        fakens     = options.fakens
        
        print "[*] --- fake options ---"
        if options.fakedomains:
            for domain in options.fakedomains.split(','):

                # Make domain case insensitive
                domain = domain.lower()
                domain = domain.strip()

                if fakeip:
                    nametodns["A"][domain] = fakeip
                    print "[+] Cooking A replies to point to %s matching: %s" % (options.fakeip, domain)

                if fakeipv6:
                    nametodns["AAAA"][domain] = fakeipv6
                    print "[+] Cooking AAAA replies to point to %s matching: %s" % (options.fakeipv6, domain)

                if fakemail:
                    nametodns["MX"][domain] = fakemail
                    print "[+] Cooking MX replies to point to %s matching: %s" % (options.fakemail, domain)

                if fakealias:
                    nametodns["CNAME"][domain] = fakealias
                    print "[+] Cooking CNAME replies to point to %s matching: %s" % (options.fakealias, domain)

                if fakens:
                    nametodns["NS"][domain] = fakens
                    print "[+] Cooking NS replies to point to %s matching: %s" % (options.fakens, domain)
                  
        elif options.truedomains:
            for domain in options.truedomains.split(','):

                # Make domain case insensitive
                domain = domain.lower()
                domain = domain.strip()

                if fakeip:
                    nametodns["A"][domain] = False
                    print "[+] Cooking A replies to point to %s not matching: %s" % (options.fakeip, domain)
                    nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = fakeip

                if fakeipv6:
                    nametodns["AAAA"][domain] = False
                    print "[+] Cooking AAAA replies to point to %s not matching: %s" % (options.fakeipv6, domain)
                    nametodns["AAAA"]['*.*.*.*.*.*.*.*.*.*'] = fakeipv6

                if fakemail:
                    nametodns["MX"][domain] = False
                    print "[+] Cooking MX replies to point to %s not matching: %s" % (options.fakemail, domain)
                    nametodns["MX"]['*.*.*.*.*.*.*.*.*.*'] = fakemail

                if fakealias:
                    nametodns["CNAME"][domain] = False
                    print "[+] Cooking CNAME replies to point to %s not matching: %s" % (options.fakealias, domain)
                    nametodns["CNAME"]['*.*.*.*.*.*.*.*.*.*'] = fakealias

                if fakens:
                    nametodns["NS"][domain] = False
                    print "[+] Cooking NS replies to point to %s not matching: %s" % (options.fakens, domain)
                    nametodns["NS"]['*.*.*.*.*.*.*.*.*.*'] = fakealias
                  
        else:

            # NOTE: '*.*.*.*.*.*.*.*.*.*' domain is a special ANY domain
            #       which is compatible with the wildflag algorithm above.

            if fakeip:
                nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = fakeip
                print "[+] Cooking all A replies to point to %s" % fakeip

            if fakeipv6:
                nametodns["AAAA"]['*.*.*.*.*.*.*.*.*.*'] = fakeipv6
                print "[+] Cooking all AAAA replies to point to %s" % fakeipv6

            if fakemail:
                nametodns["MX"]['*.*.*.*.*.*.*.*.*.*'] = fakemail
                print "[+] Cooking all MX replies to point to %s" % fakemail

            if fakealias:
                nametodns["CNAME"]['*.*.*.*.*.*.*.*.*.*'] = fakealias
                print "[+] Cooking all CNAME replies to point to %s" % fakealias

            if fakens:
                nametodns["NS"]['*.*.*.*.*.*.*.*.*.*'] = fakens
                print "[+] Cooking all NS replies to point to %s" % fakens
    
        print "[*] --- "
    
    # Proxy all DNS requests
    if not options.fakeip and not options.fakeipv6 and not options.fakemail and not options.fakealias and not options.fakens and not options.file:
        print "[*] No parameters were specified. Running in full proxy mode"    

    # Launch DNSSECChef
    start_cooking(interface=options.interface, nametodns=nametodns, nameservers=nameservers, udp=options.udp, tcp=options.tcp, ipv6=options.ipv6, port=options.port, logfile=options.logfile)
