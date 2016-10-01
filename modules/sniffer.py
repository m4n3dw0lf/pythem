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
#from modules.utils import *
from datetime import datetime
import socket
import re
from utils import *
import sys

class Sniffer(object):

	name = "Sniffer"
	desc = "Custom scapy sniffer."
	version = "1.2"

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
					try:
						print pkt
						print "[DNS Layer]"
						print
						print "[DNS Query]"
						print
						print "[D] qname: {}".format(p.getlayer(DNS).qd.qname)
						print end
					except:
						pass
				elif p.haslayer(DNSRR):
					try:
						print pkt
						print "[DNS Layer]"
						print
						print "[DNS Response]"
						print
						print "[D] rrname: {}".format(p[DNSRR].rrname)
						print "[D] rdata: {}".format(p[DNSRR].rdata)
						print end
					except:
						pass
				elif p.haslayer(DHCP):
					mtype = p[DHCP].options
					if mtype[0][1] == 1:
						msg_type = "[D] DHCP Discover message.\n"
						try:
							for x,y in mtype:
								if x == "client_id":
									msg_type += " |_Client-id: {}\n".format(y)
								if x == "vendor_class_id":
									msg_type += " |_Vendor-id: {}\n".format(y)
								if x == "hostname":
									msg_type += " |_Hostname: {}\n".format(y)
						except:
							pass
					elif mtype[0][1] == 2:
						msg_type = "[D] DHCP Offer message.\n"
						try:
							for x,y in mtype:
								if x == "server_id":
									msg_type += " |_DHCP Server: {}\n".format(y)
								if x == "broadcast_address":
									msg_type += " |_Broadcast: {}\n".format(y)
								if x == "router":
									msg_type += " |_Router: {}\n".format(y)
								if x == "domain":
									msg_type += " |_Domain: {}\n".format(y)
								if x == "name_server":
									msg_type += " |_DNS Server: {}\n".format(y)
						except:
							pass

					elif mtype[0][1] == 3:
						msg_type = "[D] DHCP Request message.\n"
						try:
							for x,y in mtype:
								if x == "requested_addr":
									msg_type += " |_Request address: {}\n".format(y)
								if x == "hostname":
									msg_type += " |_Hostname: {}\n".format(y)
						except:
							pass
					elif mtype[0][1] == 4:
						msg_type = "[D] DHCP Decline message."

					elif mtype[0][1] == 5:
						msg_type = "[D] DHCP Acknowledgment message.\n"
						try:
							for x,y in mtype:
								if x == "server_id":
									msg_type += " |_DHCP Server: {}\n".format(y)
								if x == "broadcast_address":
									msg_type += " |_Broadcast: {}\n".format(y)
								if x == "router":
									msg_type += " |_Router: {}\n".format(y)
								if x == "domain":
									msg_type += " |_Domain: {}\n".format(y)
								if x == "name_server":
									msg_type += " |_DNS Server: {}\n".format(y)
						except:
							pass
					elif mtype[0][1] == 6:
						msg_type = "[D] DHCP Negative Acknowledgment message."
					elif mtype[0][1] == 7:
						msg_type = "[D] DHCP Release message."
					elif mtype[0][1] == 8:
						msg_type = "DHCP informational message.\n"
						try:
							for x,y in mtype:
								if x == "server_id":
									msg_type += " |_DHCP Server: {}\n".format(y)
								if x == "broadcast_address":
									msg_type += " |_Broadcast: {}\n".format(y)
								if x == "router":
									msg_type += " |_Router: {}\n".format(y)
								if x == "domain":
									msg_type += " |_Domain: {}\n".format(y)
								if x == "name_server":
									msg_type += " |_DNS Server: {}\n".format(y)
						except:
							pass
					else:
						msg_type = "[!] INVALID MESSAGE TYPE"

					print pkt
					print "[DHCP Layer]"
					print
					print msg_type
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
				if load.startswith('GET') or load.startswith('POST') or load.startswith('HTTP') or "230" in load:
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
				if type == 0:
					print "[I] Echo-reply."
				elif type == 3:
					print "[I] Destination Unreachable."
				elif type == 5:
					print "[I] Redirect."
				elif type == 8:
					print "[I] Echo-request."
				elif type == 32:
					print "[I] Mobile Host Redirect."
				elif type == 33:
					print "[I] IPv6 Where-Are-You."
				elif type == 34:
					print "[I] IPv6 I-Am-Here."
				elif type == 37:
					print "[I] Domain Name Request."
				elif type == 38:
					print "[I] Domain Name Reply."
				print "[I] Type: {}".format(type)
				print "[I] Code: {}".format(type)
				print end



	def coresniff(self, p):
			# ARP Core events
		if p.haslayer(ARP):
				# who-has
			if p[ARP].op == 1:
				print color("[ARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Request: " + p[ARP].psrc + " who has " + p[ARP].pdst + "?"
				# is-at
			if p[ARP].op == 2:
				print color("[ARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Response: " + p[ARP].psrc + " is at " + p[ARP].hwsrc

			# ICMP Core events
		elif p.haslayer(ICMP):
			type = p[ICMP].type
			if p[ICMP].type == 0:
                        	type = "echo-reply."
                        elif type == 3:
                        	type = "destination unreachable."
                        elif type == 5:
                                type = "redirect."
                        elif type == 8:
                                type = "echo-request."
                        elif type == 32:
                        	type = "mobile host redirect."
                        elif type == 33:
                                type = "IPv6 where-are-you."
                        elif type == 34:
                                type = "IPv6 i-am-here."
                        elif type == 37:
                                type = "domain name request."
                        elif type == 38:
                                type = "domain name reply."

			print color("[ICMP] ","red") + p[IP].src + " ---> " + p[IP].dst + " {} ".format(type)

			# UDP Core events
		elif p.haslayer(UDP):
			if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
				try:

					print color("[DNS] ","blue") + p[IP].src + " ---> " + p[IP].dst + " domain name query: " + "{}".format(p.getlayer(DNS).qd.qname)
				except:
					pass

			elif p.haslayer(DNSRR):
				try:
					print color("[DNS] ","blue") + p[IP].src + " ---> " + p[IP].dst + " domain name response: " + "{}".format(p[DNSRR].rdata)
				except:
					pass
				# DHCP Message types
			elif p.haslayer(DHCP):
				mtype = p[DHCP].options
				if mtype[0][1] == 1:
					msg_type = "DHCP Discover message: "
					try:
						for x,y in mtype:
							if x == "client_id":
								msg_type += "client-id is {} , ".format(y)
							if x == "vendor_class_id":
								msg_type += "vendor-id is {} , ".format(y)
							if x == "hostname":
								msg_type += "hostname is {} , ".format(y)
					except:
						pass
				elif mtype[0][1] == 2:
					msg_type = "DHCP offer message: "
                                        try:
                                        	for x,y in mtype:
                                                	if x == "server_id":
                                                       		msg_type += "DHCP server at {} , ".format(y)
                                                        if x == "broadcast_address":
                                                        	msg_type += "broadcast is {} , ".format(y)
                                                        if x == "router":
                                                        	msg_type += "router at {} , ".format(y)
                                                        if x == "domain":
                                                                msg_type += "domain is {} , ".format(y)
                                                       	if x == "name_server":
                                                        	msg_type += "DNS server at {} , ".format(y)
                                        except:
                                        	pass

				elif mtype[0][1] == 3:
					msg_type = "DHCP request message: "
					try:
						for x,y in mtype:
							if x == "requested_addr":
								msg_type += "request address {} , ".format(y)
							if x == "vendor_class_id":
								msg_type += "hostname is {} , ".format(y)
					except:
						pass
				elif mtype[0][1] == 4:
					msg_type = "DHCP decline message."
				elif mtype[0][1] == 5:
					msg_type = "DHCP acknowledgment message: "
                                        try:
                                        	for x,y in mtype:
                                                	if x == "server_id":
                                                       		msg_type += "DHCP server at {} , ".format(y)
                                                        if x == "broadcast_address":
                                                        	msg_type += "broadcast is {} , ".format(y)
                                                        if x == "router":
                                                        	msg_type += "router at {} , ".format(y)
                                                        if x == "domain":
                                                                msg_type += "domain is {} , ".format(y)
                                                       	if x == "name_server":
                                                        	msg_type += "DNS server at {} , ".format(y)
                                        except:
                                        	pass

				elif mtype[0][1] == 6:
					msg_type = "DHCP negative Acknowledgment message."
				elif mtype[0][1] == 7:
					msg_type = "DHCP release message."
				elif mtype[0][1] == 8:
					msg_type = "DHCP informational message."
					try:
						for x,y in mtype:
							if x == "server_id":
								msg_type += "DHCP server at {} , ".format(y)
							if x == "broadcast_address":
								msg_type += "broadcast is {} , ".format(y)
							if x == "router":
								msg_type += "router at {} , ".format(y)
							if x == "domain":
								msg_type += "domain is {} , ".format(y)
							if x == "name_server":
								msg_type += "DNS server at {} , ".format(y)
					except:
						pass
				else:
					msg_type = "[!] INVALID MESSAGE TYPE"
				print color("[DHCP] ","magenta") + p[Ether].src + " ---> " + p[Ether].dst + " : " + msg_type

			# TCP Core events
		elif p.haslayer(TCP) and p.haslayer(Raw):
	    		user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Ll]ogin|[Ll]ogin[Ii][Dd]|[Uu]name|[Uu]suario)=([^&|;]*)'
            		pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
			pxy_regex = '([Ww]ww-[Aa]uthorization:|[Ww]ww-[Aa]uthentication:|[Pp]roxy-[Aa]uthorization:|[Pp]roxy-[Aa]uthentication:) Basic (.*?) '

			load = str(p[Raw].load).replace("\n"," ")
			if load.startswith('GET'):
				method = load.split("GET")
				get = str(method[1]).split("HTTP")
				try:
					ghost = socket.gethostbyaddr(str(p[IP].dst))
					host = "{}/{}".format(ghost[0],str(p[IP].dst))
				except:
					host = str(p[IP].dst)

				print color("[TCP] ","white") + p[IP].src + " ---> "+ host +" - GET: " + get[0]
			elif load.startswith('USER'):
				method = load.split("USER")
				user = str(method[1]).split("\r")
				print "\n" + color("[$$$] FTP Login found: ","yellow") + ''.join(user) + "\n"
			elif load.startswith('PASS'):
				method = load.split("PASS")
				passw = str(method[1]).split("\r")
				print "\n" + color("[$$$] FTP Password found: ","yellow") + ''.join(passw) + "\n"
			else:
				users = re.findall(user_regex, load)
				passwords = re.findall(pw_regex, load)
			        proxy = re.findall(pxy_regex, load)
				self.creds(users,passwords,proxy)

	def creds(self,users,passwords,proxy):
	        if users:
			print "\n" + color("[$$$] Login found: ","yellow") + str(users[0][1]) + "\n"
       		if passwords:
	                print "\n" + color("[$$$] Password found: ","yellow") + str(passwords[0][1]) + "\n"
		if proxy:
			try:
				print "\n" + color("[$$$] Proxy credentials: ","yellow") + str(proxy[0][1]).decode('base64') + "\n"
			except:
				print "\n" + color("[$$$] Proxy credentials: ","yellow") + str(proxy[0][1]) + "\n"

	def start(self):
		if self.filter == None:
			self.filter = 'core'
		if self.filter == "core":
			if self.wrpcap == 'y':
				try:
					p = sniff(iface=self.interface, prn = self.coresniff)
					time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
					wrpcap("pythem{}.pcap".format(time),p)
					print "\n[!] PytheM sniffer finalized."
				except Exception as e:
					if "Interrupted system call" in e or "not found" in e:
						self.start()
					else:
						print "[!] Exception caught: {}".format(e)
			else:
				try:
					p = sniff(iface=self.interface,prn =self.coresniff)
					print "\n[!] PytheM sniffer finalized."
				except Exception as e:
					if "Interrupted system call" in e or "not found" in e:
						self.start()
					else:
						print "[!] Exception caught: {}".format(e)


		else:
			if self.wrpcap == 'y':
				try:
					p = sniff(iface=self.interface,filter = "{}".format(self.filter), prn = self.customsniff)
				        time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                        	       	wrpcap("pythem{}.pcap".format(time),p)
					print "\n[!] PytheM sniffer finalized."
				except Exception as e:
					if "Interrupted system call" in e or "not found" in e:
						self.start()
					else:
						print "[!] Exception caught: {}".format(e)

			else:
				try:
					p = sniff(iface=self.interface,filter ="{}".format(self.filter), prn = self.customsniff, store = 0)
					print "\n[!] PytheM sniffer finalized."
				except Exception as e:
					if "Interrupted system call" in e or "not found" in e:
						self.start()
					else:
						print "[!] Exception caught: {}".format(e)


if __name__ == "__main__":

		# Change the import for utils to run sniffer alone.
	try:
		if sys.argv[1] == "-h" or sys.argv[1] == "--help":
			print "[PytheM Sniffer]"
			print
			print "usage:"
			print "  python sniffer.py interface filter"
			print
			print "run default:"
			print "  python sniffer.py"
		else:
			Sniffer = Sniffer(sys.argv[2],sys.argv[3])
			Sniffer.start()
	except IndexError:
		print "[+] Starting Default Sniffer"
		print "[PytheM Sniffer initialized]"
		Sniffer = Sniffer(None,None)
		Sniffer.start()

	except Exception as e:
		print "[!] Exception caught: {}".format(e)

