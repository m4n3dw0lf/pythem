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
from subprocess import *
import socket


class SimpleFuzz(object):
    name = "Fuzzer"
    desc = "Used in the xploit module. simple 'A' generation through tcp or stdin"
    version = "0.3"

    def __init__(self):
        self.offset = None
        self.target = None

    def stdinfuzz(self,target,offset):
        self.target = target
        self.offset = offset
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
