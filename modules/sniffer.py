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
	desc = "Custom scapy sniffer."
	version = "0.6"

	def __init__(self, interface, filter):
		self.interface = interface
		self.filter = filter
		self.wrpcap = raw_input("[*] Wish to write a .pcap file with the results in the actual directory?[y/n]: ")


	def customsniff(self, p):

                if p.haslayer(TCP) and not p.haslayer(Raw):
                	return

		print "\r\n\n\n--------------------------[Packet]--------------------------\r\n"

		if p.haslayer(Ether):
			mac_dst = p[Ether].dst
			mac_src = p[Ether].src
			#type = p[Ether].type
			print
			print "[Ethernet Layer]"
			print
			print "[E] MAC destination: {}".format(mac_dst)
			print "[E] MAC source: {}".format(mac_src)
			#print "[E] Type: {}".format(type)
			print

		if p.haslayer(ARP):

			if p[ARP].op == 1:
				print "[ARP Layer]"
				print
				print "[A] Request: " + p[ARP].psrc + " who has " + p[ARP].pdst + "?"
			if p[ARP].op == 2:
				print "[ARP Layer]"
				print
				print "[A] Response: " + p[ARP].hwsrc + " is at " + p[ARP].psrc

		elif p.haslayer(IP):
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			len = p[IP].len
			ttl = p[IP].ttl
			print "[IPv4 Layer]"
        	        print
        	        print "[I] IPv4 destination: {}".format(ip_dst)
        	        print "[I] IPv4 source: {}".format(ip_src)
        	        print "[I] Packet lenght: {}".format(len)
        	        print "[I] Time to Live: {}".format(ttl)
        	        print

			if p.haslayer(UDP):
				sport = p[UDP].sport
				dport = p[UDP].dport
				print "[UDP Layer]"
				print
				print "[U] Source port: {}".format(sport)
				print "[U] Destination port: {}".format(dport)
				print
				if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
					print "[DNS Layer]"
					print
					print "REQUEST"
					print
					print "[D] Domain name: {}".format(p.getlayer(DNS).qd.qname)
					print
				elif p.haslayer(DNSRR):
					print "[DNS Layer]"
					print
					print "RESPONSE"
					print
					print "[D] Host: {}".format(p[DNSRR].rdata)
					print
	                        else:
 	                                print "[Could not parse packet]"
        	                        print
                	                p.show()



			elif p.haslayer(TCP) and p.haslayer(Raw):
				flags = {'F':'FIN','S':'SYN','R':'RST','P':'PSH','A':'ACK','U':'URG','E':'ECE','C':'CWR'}
				dport = p[TCP].dport
				sport = p[TCP].sport
				ack = p[TCP].ack
				seq = p[TCP].seq
				preflag = [flags[x] for x in p.sprintf('%TCP.flags%')]
				flag = "/".join(preflag)
				chksum = p[TCP].chksum
				load = p[Raw].load
				if load.startswith('GET') or load.startswith('POST') or load.startswith('HTTP'):
					print "[TCP Layer]"
					print
                        	     	print "[T] Source port: {}".format(sport)
					print "[T] Destination port: {}".format(dport)
					print "[T] Seq: {}".format(seq)
					print "[T] Ack: {}".format(ack) 
					print "[T] Flags: {}".format(flag)
					print "[T] Checksum: {}".format(chksum)
					print
					print "[LOAD]"
					print
					print "[R] Load:\n\n{}".format(load)
					print
					print

				else:
					print "[TCP Layer]"
					print
					print "[T] Source port: {}".format(sport)
					print "[T] Destination port: {}".format(dport)
					print "[T] Seq: {}".format(seq)
					print "[T] Ack: {}".format(ack)
					print "[T] Flags: {}".format(flag)
					print "[T] Checksum: {}".format(chksum)
					print
					print "[Packet don't have GET, POST or HTTP on load.]"

			elif p.haslayer(ICMP):
				type = p[ICMP].type
				code = p[ICMP].code
				print "[ICMP Layer]"
				print
				print "[I] Type: {}".format(type)
				print "[I] Code: {}".format(type)


		else:
			print "[Could not parse packet]"
			print
			p.show()

		print "------------------------------------------------------------"



	def start(self):
		if self.filter == None:
			self.filter = ''
		if self.wrpcap == 'y':
			print "[+] Custom sniffer initialized"
			try:

				p = sniff(iface=self.interface,filter = "{}".format(self.filter), prn = self.customsniff)
			        time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                               	wrpcap("pythem{}.pcap".format(time),p)
			except Exception as e:
				if "Interrupted system call" in e:
					pass

		else:
			print "[+] Custom sniffer initialized"
			p = sniff(iface=self.interface,filter ="{}".format(self.filter), prn = self.customsniff, store = 0)
			print "\n[!] User requested shutdown."
