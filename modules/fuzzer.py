#!/usr/bin/env python2.7

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


import os
import sys
import struct
import resource
import time
from netaddr import IPAddress, AddrFormatError
from subprocess import *
from socket import *

class SimpleFuzz(object):

	def __init__(self, target, type):
		self.target = target
		if type == "tcp":
			self.port = input("[+]Enter the tcp port to fuzz: ")
			self.tcpfuzz()
		elif type == "stdin":
			self.stdinfuzz()
		else:
			print "[!] Select a valid fuzzer type (stdin or tcp)."

	def stdinfuzz(self):

		buf = ''
		while True:
			try:
				buf += '\x41'
				resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
				resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
				P = Popen(self.target, stdin=PIPE)
				print "[*] Sending buffer with lenght: "+str(len(buf))
				P.stdin.write(buf+ "\n")
				line = sys.stdin.readline()
				P.poll()
				ret = P.returncode
				if ret is None:
					continue
				else:
					if ret == -11:
						print "\n[*] Child program crashed with SIGSEGV\n"
						print "\n[*] Hit enter to continue.\n"
						continue

					elif ret < 0 and ret >= -7:
						print "\n[+] Instruction Pointer may be at: {}\n".format(str(len(buf)))
						break
					else:
						print "\n[*] Child program exited with code %d\n" % ret
						print "\n[*] Hit enter to continue.\n"
						continue


			except KeyboardInterrupt:
				break



	def tcpfuzz(self):
		buf = ''
		try:
			self.target = str(IPAddress(self.target))
		except AddrFormatError as e:
			print "[-] Select a valid IP Address as target."
			return
		while True:
			try:
				self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.socket.settimeout(2)
				self.socket.connect((self.target,self.port))
				#self.socket.recv(1024)
				buf = '\x41'
				print "[+] TCP fuzzing initialized, wait untill crash."
				while True:
					self.socket.send(buf)
					buf += '\x41'
				self.socket.recv(1024)

			except KeyboardInterrupt:
				break
			except Exception as e:
				if 'Connection refused' in e:
					print "[-] Connection refused."
					break
				else:
					print "[+] Crash occured with buffer length: {}".format(str(len(buf)))
					break

