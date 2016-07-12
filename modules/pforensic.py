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
import sys
import os

class PcapReader(object):


	def __init__(self, file):
		self.file = file
		self.packets = rdpcap(file)
	def printHelp(self):
		print """\n


		[ PytheM - Leitor Forense de arquivos pcap ]

	ARQUIVO - [ {} ]

[*] help:   			Print this help message

[*] clear:			Clean the screen, same as GNU/Linux OS "clear"

[*] exit/quit:			Return to pythem


[*] show:			Display all the packets and their index numbers.

[*] conversations:		Display pictogram with conversations between hosts from the analyzed file.


[*] packetdisplay [num]:	Display the full content of index selected packet.

[*] packetload [num]:		Display the payload of index selected packet.


""".format(self.file)	


	def filter_lookup(self,p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(Raw):
				print
				print "----------------------------------------------[PACKET]-------------------------------------------------------\n"
				print str(ip_src) + "---->" + str(ip_dst) + "\n" 
				print "\n".join(p.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")) 		
				print "-------------------------------------------------------------------------------------------------------------"
				print
	def start(self):
		while True:
			try:
				self.command = raw_input("pforensic> ")
				self.argv = self.command.split()
				self.input_list = [str(a) for a in self.argv]


				try:
                                	if self.input_list[0]  == 'packetdisplay':
                                	        try:self.packets[int(self.input_list[1])].show()
						except Exception as e: print "[!] Exception caught: {}".format(e)
		

					elif self.input_list[0] == 'packetload':
						try:
							print "[+] Packet {} payload: ".format(self.input_list[1])
							self.filter_lookup(self.packets[int(self.input_list[1])])
						
						except Exception as e: print "[!] Exception caught: {}".format(e)
	
					elif self.input_list[0]  == 'exit':
						break
					elif self.input_list[0] == 'quit':
						break
					elif self.input_list[0] == 'help':
						self.printHelp()
					elif self.input_list[0] == 'clear':
						os.system('clear')
					elif self.input_list[0] == 'ls':
						os.system('ls')
					elif self.input_list[0] == 'summary':
						try:self.packets.summary()
						except Exception as e: print "[!] Exception caught: {}".format(e)
					elif self.input_list[0] == 'show':
						try:self.packets.show()
						except Exception as e: print "[!] Exception caught: {}".format(e)	
					elif self.input_list[0] == 'conversations':
						try:self.packets.conversations()
						except Exception as e: print "[!] Exception caught: {}".format(e)
					else:
						print "[-] Select a valid option."				

                        	except IndexError:
					pass
			except KeyboardInterrupt:
                               	 break





