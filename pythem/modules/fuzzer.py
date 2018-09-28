#!/usr/bin/env python2.7

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


import os
import sys
import struct
import resource
import time
from netaddr import IPAddress, AddrFormatError
from subprocess import *
import socket


class SimpleFuzz(object):
    name = "Fuzzer"
    desc = "Used in the xploit module. simple 'A' generation through tcp or stdin"
    version = "0.3"

    def __init__(self, target, type, offset):
        self.offset = offset
        self.target = target
        if type == "test":
            return
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
                first = True
                buf += '\x41' * self.offset
                resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
                resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
                P = Popen(self.target, stdin=PIPE)
                print "[*] Sending buffer with lenght: " + str(len(buf))
                P.stdin.write(buf + '\n')
                line = sys.stdin.readline()
                P.poll()
                ret = P.returncode

                if ret is None:
                    continue
                else:
                    if ret == -4:
                        print "\n[+] Instruction Pointer may be at: {}\n".format(str(len(buf)))
                        break
                    elif ret == -7:
                        print "\n[+] Instruction Pointer may be near: {}\n".format(str(len(buf)))
                        print "[*] Child program crashed with code: %d\n" % ret
                        continue
                    elif ret == -11:
                        print "[*] Child program crashed with SIGSEGV code: %d\n" % ret
                        print "\n[*] Hit enter to continue.\n"
                        continue
                    else:
                        print "[*] Child program exited with code: %d\n" % ret
                        print "\n[*] Hit enter to continue.\n"
                        continue


            except KeyboardInterrupt:
                break

    def tcpfuzz(self):
        buf = ''
        try:
            self.target = str(IPAddress(self.target))
        except AddrFormatError as e:
            try:
                self.target = socket.gethostbyname(self.target)
            except Exception as e:
                print "[-] Select a valid IP Address as target."
                print "[!] Exception caught: {}".format(e)
                return

        buf = '\x41' * self.offset
        print "[+] TCP fuzzing initialized, wait untill crash."
        while True:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(2)
                self.socket.connect((self.target, self.port))
                print "[+] Fuzzing with [{}] bytes.".format(len(buf))

                try:
                    response = self.socket.recv(1024)
                    print "[*] Response: {}".format(response)
                    self.socket.send(buf)

                    try:
                        response = self.socket.recv(1024)
                        print "[*] Response: {}".format(response)
                        self.socket.close()
                        buf += '\x41' * self.offset
                    except:
                        self.socket.close()
                        buf += '\x41' * self.offset
                except:
                    self.socket.send(buf)
                    try:
                        response = self.socket.recv(1024)
                        print "[*] Response: {}".format(response)
                        self.socket.close()
                        buf += '\x41' * self.offset
                    except:
                        self.socket.close()
                        buf += '\x41' * self.offset

            except KeyboardInterrupt:
                break
            except Exception as e:
                if 'Connection refused' in e:
                    print "[-] Connection refused."
                    time.sleep(4)

                else:
                    try:
                        response = self.socket.recv(1024)
                        print "[*] Response: {}".format(response)
                    except Exception as e:
                        if 'timed out' in e:
                            print "[-] Timed out."
                            time.sleep(2)

                    print "[+] Crash occured with buffer length: {}".format(str(len(buf)))
                    print "[!] Exception caught: {}".format(e)
