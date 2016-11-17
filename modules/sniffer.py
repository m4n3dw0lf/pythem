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
	obs = "TO DO: Decompress data and generate images on http sniffer"

	def __init__(self, interface, filter):
		self.interface = interface
		self.filter = filter
		self.wrpcap = raw_input("[*] Wish to write a .pcap file with the sniffed packets in the actual directory?[y/n]: ")
		self.packetcounter = 0
	def customsniff(self, p):
		self.packetcounter += 1
		print "\n------------------------------[PACKET N:{}]------------------------------".format(self.packetcounter)
		p.show()
		print "-------------------------------------------------------------------------\n"

	def httpsniff(self, p):
		try:
			if p.haslayer(TCP):
				if p.haslayer(Raw):
					if p[Raw].load.startswith('GET') or p[Raw].load.startswith('POST'):
						print "\n------------------------------[PACKET N:{}]------------------------------".format(self.packetcounter)
						print color("CLIENT: ","blue") + p[IP].dst + " ---> " + color("SERVER: ","red") + p[IP].dst
						print "  FLAGS:{} SEQ:{} ACK:{}\n".format(p.sprintf('%TCP.flags%'),p[TCP].seq, p[TCP].ack)
						print color("\nLoad:\n","yellow")
						try:
							header,body = p[Raw].load.split("\r\n\r\n")
							print color("\nHeaders:\n","yellow")
							print header
							print color("\nBody:\n","yellow")
							print body
						except:
							print color("\nCouldn't split header and body, printing load anyway:\n","red")
							print p[Raw].load
						print "-------------------------------------------------------------------------\n"

					if p[Raw].load.startswith('HTTP'):
						print color("SERVER: ","red") + p[IP].dst + " ---> " + color("CLIENT: ","blue") + p[IP].dst
						print "  FLAGS:{} SEQ:{} ACK:{}\n".format(p.sprintf('%TCP.flags%'),p[TCP].seq, p[TCP].ack)
						print color("\nLoad:\n","yellow")
						try:
							header,body = p[Raw].load.split("\r\n\r\n")
							print color("\nHeaders:\n","yellow")
							print header
							for l in str(header).split("\n"):
								if l.startswith("Content-Encoding:"):
									print color("\nBody encoded:","red") + l.strip("Content-Encoding:") + "\n"
								if l.startswith("Content-Type: image/"):
									print color("\n Image found, format:","red") + l.strip("Content-Type:") + "\n"
							print color("\nBody:\n","yellow")
							print body
						except:
							print color("\nCouldn't split header and body, printing load anyway:\n","red")
							print p[Raw].load
						print "-------------------------------------------------------------------------\n"
				else:
					pass
         	except Exception as e:
                	print "[!]Exception caught: {}".format(e)
                	pass

	def coresniff(self, p):
			# ARP Core events
	   try:
		if p.haslayer(ARP):
				# who-has
			if p[ARP].op == 1:
				print color("[ARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Request: " + p[ARP].psrc + color(" who has ","blue") + p[ARP].pdst + "?"
				# is-at
			elif p[ARP].op == 2:
				print color("[ARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Response: " + p[ARP].psrc + color(" is at ","red") + p[ARP].hwsrc
			elif p[ARP].op == 3:
				print color("[RARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Request: " + p[Ether].src + color(" IP address of MAC ","blue") + p[ARP].hwdst + "?"
			elif p[ARP].op == 4:
				print color("[RARP] ","grey") + p[ARP].hwsrc + " ---> " + p[ARP].hwdst + " Response: " + p[Ether].src + color(" IP address is ","red") + p[ARP].psrc
			# ICMP Core events
		elif p.haslayer(ICMP):
			type = p[ICMP].type
			if p[ICMP].type == 0:
                        	type = color("echo-reply.","red")
                        elif type == 3:
                        	type = color("destination unreachable.","grey")
                        elif type == 5:
                                type = color("redirect.","yellow")
                        elif type == 8:
                                type = color("echo-request.","blue")
                        elif type == 32:
                        	type = color("mobile host redirect.","yellow")
                        elif type == 33:
                                type = color("IPv6 where-are-you.","blue")
                        elif type == 34:
                                type = color("IPv6 i-am-here.","red")
                        elif type == 37:
                                type = color("domain name request.","blue")
                        elif type == 38:
                                type = color("domain name reply.","red")

			print color("[ICMP] ","white") + p[IP].src + " ---> " + p[IP].dst + " {} ".format(type)

			# UDP Core events
		elif p.haslayer(UDP):
			if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
				try:

					print color("[DNS] ","blue") + "{}:{}".format(p[IP].src, str(p[UDP].sport)) + " ---> " + "{}:{}".format(p[IP].dst, str(p[UDP].dport)) + " domain name "+ color("query: ","blue") + color("{}".format(p.getlayer(DNS).qd.qname),"yellow")
				except:
					pass

			elif p.haslayer(DNSRR):
				try:
					print color("[DNS] ","blue") + p[IP].src + ":" + str(p[UDP].sport) + " ---> " + p[IP].dst + ":" + str(p[UDP].dport) + " domain name "+ color("response: ","red") + color("{}".format(p[DNSRR].rdata),"yellow")
				except:
					pass
				#DHCP Message types
			elif p.haslayer(DHCP):
				mtype = p[DHCP].options
				if mtype[0][1] == 1:
					msg_type = "DHCP "+ color("Discover","blue") + " message: "
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
					msg_type = "DHCP "+ color("Offer","red")+" message: "
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
					msg_type = "DHCP "+ color("Request","blue")+" message: "
					try:
						for x,y in mtype:
							if x == "requested_addr":
								msg_type += "request address {} , ".format(y)
							if x == "vendor_class_id":
								msg_type += "hostname is {} , ".format(y)
					except:
						pass
				elif mtype[0][1] == 4:
					msg_type = "DHCP "+ color("Decline","grey")+" message."
				elif mtype[0][1] == 5:
					msg_type = "DHCP "+ color("Acknowledgment","red")+" message: "
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
					msg_type = "DHCP "+ color("Negative Acknowledgment","grey")+" message."
				elif mtype[0][1] == 7:
					msg_type = "DHCP "+ color("Release","magenta")+" message."
				elif mtype[0][1] == 8:
					msg_type = "DHCP "+ color("Informational","magenta")+" message."
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
				print color("[DHCP] ","magenta") + p[Ether].src + " ---> " + p[Ether].dst + " : " + color(msg_type,"yellow")

			# TCP Core events
		elif p.haslayer(TCP): 
			if p.haslayer(Raw):
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

					print color("[TCP]({})".format(p.sprintf('%TCP.flags%')),"red") + p[IP].src + ":" + str(p[TCP].sport) + " ---> "+ host +":"+str(p[TCP].dport) +" - " + color("GET: {}".format(get[0]),"yellow")

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
			#else:
				#print color("[TCP]({})".format(p.sprintf('%TCP.flags%')),"white") + p[IP].src + ":" + str(p[TCP].sport) + " ---> " + p[IP].dst + ":"+str(p[TCP].dport) + " seq: {} /ack: {}".format(p[TCP].seq,p[TCP].ack)
           except Exception as e:
		print "[!]Exception caught: {}".format(e)
		pass

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
		print "FILTER: " + self.filter
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

		elif self.filter == 'http':
                        if self.wrpcap == 'y':
                                try:
                                        p = sniff(iface=self.interface, prn = self.httpsniff)
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
                                        p = sniff(iface=self.interface,prn = self.httpsniff)
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

