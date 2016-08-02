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
	version = "0.8"

	def __init__(self, interface, filter):
		self.interface = interface
		self.filter = filter
		self.wrpcap = raw_input("[*] Wish to write a .pcap file with the results in the actual directory?[y/n]: ")


	def customsniff(self, p):

		if p.haslayer(Ether):
			pkt = "\r\n\n\n--------------------------[Packet]--------------------------\r\n"
			end = "\r\n------------------------------------------------------------\r\n"
			mac_dst = p[Ether].dst
			mac_src = p[Ether].src
			#type = p[Ether].type
			pkt += "\n[Ethernet Layer]\n\n"
			pkt += "[E] MAC destination: {}\n".format(mac_dst)
			pkt += "[E] MAC source: {}\n\n".format(mac_src)
			#print "[E] Type: {}".format(type)

		if p.haslayer(ARP):

			if p[ARP].op == 1:
				print pkt
				print "[ARP Layer]"
				print
				print "[A] Request: " + p[ARP].psrc + " who has " + p[ARP].pdst + "?"
				print end
			if p[ARP].op == 2:
				print pkt
				print "[ARP Layer]"
				print
				print "[A] Response: " + p[ARP].psrc + " is at " + p[ARP].hwsrc
				print end

		elif p.haslayer(IP):
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			ip_chk = p[IP].chksum
			len = p[IP].len
			ttl = p[IP].ttl
			pkt += "[IPv4 Layer]\n\n"
        	        pkt += "[I] IPv4 destination: {}\n".format(ip_dst)
        	        pkt += "[I] IPv4 source: {}\n".format(ip_src)
        	        pkt += "[I] Packet lenght: {}\n".format(len)
        	        pkt += "[I] IP Checksum: {}\n".format(ip_chk)
        	        pkt += "[I] Time to Live: {}\n\n".format(ttl)

			if p.haslayer(UDP):
				sport = p[UDP].sport
				dport = p[UDP].dport
				pkt += "[UDP Layer]\n\n"
				pkt += "[U] Source port: {}\n".format(sport)
				pkt += "[U] Destination port: {}\n\n".format(dport)
				if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
					print pkt
					print "[DNS Layer]"
					print
					print "[DNS Query]"
					print
					print "[D] qname: {}".format(p.getlayer(DNS).qd.qname)
					print end

				elif p.haslayer(DNSRR):
					print pkt
					print "[DNS Layer]"
					print
					print "[DNS Response]"
					print
					print "[D] rrname: {}".format(p[DNSRR].rrname)
					print "[D] rdata: {}".format(p[DNSRR].rdata)
					print end



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
					print pkt
					print "[TCP Layer]"
					print
                        	     	print "[T] Source port: {}".format(sport)
					print "[T] Destination port: {}".format(dport)
					print "[T] Seq: {}".format(seq)
					print "[T] Ack: {}".format(ack) 
					print "[T] Flags: {}".format(flag)
					print "[T] TCP Checksum: {}".format(chksum)
					print
					print "[LOAD]"
					print
					print "[R] Load:\n\n{}".format(load)
					print end

			elif p.haslayer(ICMP):
				type = p[ICMP].type
				code = p[ICMP].code
				print pkt
				print "[ICMP Layer]"
				print
				print "[I] Type: {}".format(type)
				print "[I] Code: {}".format(type)
				print end


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
