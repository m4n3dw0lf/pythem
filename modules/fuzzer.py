#!/usr/bin/env python2.7

import os
import sys
import struct
import resource
import time
from netaddr import IPAddress, AddrFormatError
from subprocess import *
from socket import *
import socket

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
					elif ret == -4:
						print "\n[+] Instruction Pointer will be at: {}\n".format(str(len(buf)))
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

