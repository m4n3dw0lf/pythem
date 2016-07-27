#!/usr/bin/env python2.7
#coding=UTF-8

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


from scapy.all import *
from scapy.error import Scapy_Exception
from modules.utils import *
from datetime import datetime

class Sniffer(object):

	name = "Sniffer"
	desc = "Simple scapy sniffer with some pre-defined filters."
	version = "0.3"

	def __init__(self, interface, filter):
		self.interface = interface
		self.filter = filter
		self.wrpcap = raw_input("[*] Wish to write a .pcap file with the results in the actual directory?[y/n]: ")


	def DNSsniff(self, p):
		if IP in p:
			ip_src= p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
				print str(ip_src) + " --> " + str(ip_dst) + " : " + "(" + p.getlayer(DNS).qd.qname + ")"

	def HTTPsniff(self, p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(TCP) and p.getlayer(TCP).dport == 80 and p.haslayer(Raw):
                                print
                                print "----------------------------------------------[PACKET]-------------------------------------------------------\n"
                                print str(ip_src) + "---->" + str(ip_dst) + "\n"
                                print "\n".join(p.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
                                print "---------------------------------------------------------------------------------------------------------------"
                                print


	def MANUALsniff(self, p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(Raw):
                                print
                                print "----------------------------------------------[PACKET]-------------------------------------------------------\n"
                                print str(ip_src) + "---->" + str(ip_dst) + "\n"
                                print "\n".join(p.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
                                print "---------------------------------------------------------------------------------------------------------------"
                                print


	def start(self):
                if self.filter == 'http' and self.wrpcap == 'y':
			try:
				print "[+] HTTP sniffer initialized"
				p = sniff(iface=self.interface,filter = "port 80", prn = self.HTTPsniff)
                        	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)
			except KeyboardInterrupt:
				print "\n[!] User requested shutdown."


		elif self.filter == 'dns' and self.wrpcap == 'y':
			try:
				print "[+] DNS sniffer initialized"
       	                	p = sniff(iface=self.interface, filter = "port 53", prn = self.DNSsniff)
                        	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)

			except KeyboardInterrupt:
				print "\n[!] User requested shutdown."

                elif self.filter == 'http' and self.wrpcap != 'y':
                        print "[+] HTTP sniffer initialized"
                        p = sniff(iface=self.interface,filter ="port 80",prn = self.HTTPsniff, store = 0)
                        print "\n[!] User requested shutdown."


                elif self.filter == 'dns' and self.wrpcap != 'y':
                        print "[+] DNS sniffer initialized"
                        p = sniff(iface=self.interface, filter = "port 53", prn = self.DNSsniff, store = 0)
                        print "\n[!] User requested shutdown."

		else:
			if self.wrpcap != 'y':
				p = sniff(iface=self.interface, filter = "{}".format(self.filter), prn=self.MANUALsniff, store = 0)
				print "\n[!] User requested shutdown."
			elif self.wrpcap == "y":
				try:
					p = sniff(iface=self.interface, filter = "{}".format(self.filter), prn=self.MANUALsniff)
                                	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                                	wrpcap("pythem{}.pcap".format(time),p)
                                	print "\n[!] User requested shutdown."
 				except KeyboardInterrupt:
					print "\n[!] User requested shutdown."
