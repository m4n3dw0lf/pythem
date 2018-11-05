#!/usr/bin/env python2.7
# coding=UTF-8

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


from hashlib import *
from sys import argv
import os
import paramiko
import sys
import socket
from os import R_OK
import urllib2
import Queue
import urllib
import mechanize

class HashCracker(object):

    def __init__(self):
        self.hash = None
        self.wordlist = None

    def hashcrack(self, hash=None, wordlist=None):
        if not hash:
            self.hash = raw_input("[+] Enter the Hash: ")
        else:
            self.hash = hash

        if not wordlist:
            wordlist = raw_input("[+] Select file as wordlist: ")

        self.wordlist = open(wordlist, "r")
        print "[+] Supported Hashes: md5, sha1, sha224, sha256, sha512"
        hash_type = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 128: "sha512"}
        try:
            print "[+] Most likely: {}".format(hash_type[len(self.hash)])
        except:
            pass
        self.type = raw_input("[+] Hash: ")
        found = False
        if self.type.lower() == "md5":
            for word in self.wordlist:
                if md5(word).hexdigest() == self.hash:
                    print "[+] MD5 Cracked: {}".format(word)
                    found = True

        if self.type.lower() == "sha1":
            for word in self.wordlist:
                if sha1(word).hexdigest() == self.hash:
                    print "[+] SHA1 Cracked: {}".format(word)
                    found = True

        if self.type.lower() == "sha224":
            for word in self.wordlist:
                if sha224(word).hexdigest() == self.hash:
                    print "[+] SHA224 Cracked: {}".format(word)
                    found = True

        if self.type.lower() == "sha256":
            for word in self.wordlist:
                if sha256(word).hexdigest() == self.hash:
                    print "[+] SHA256 Cracked: {}".format(word)
                    found = True

        if self.type.lower() == "sha512":
            for word in self.wordlist:
                if sha512(word).hexdigest() == self.hash:
                    print "[+] SHA512 Cracked: {}".format(word)
                    found = True

        if not found:
            print "[!] Hash crack failed, try with another wordlist."


class WEBbrutus(object):
    name = "WEB brute forcer"
    desc = "Perform web password and directory brute-force"
    version = "0.3"

    def __init__(self):
        self.target_url = None
        self.wordlist = None

    def build_wordlist(self, wordlist):
        wordlist = self.wordlist
        fd = open(self.wordlist, "rb")
        raw_words = fd.readlines()
        fd.close()
        found_resume = False
        words = Queue.Queue()

        for word in raw_words:
            word = word.rstrip()
            if self.resume is not None:
                if found_resume:
                    words.put(word)
                else:
                    if word == resume:
                        found_resume = True
                        print "Resuming wordlist from: %s" % resume
            else:
                words.put(word)

        return words

    def form_attempt(self, password):
        br = mechanize.Browser()
        br.set_handle_robots(False)
        br.open(self.target_url)
        br.select_form(nr=0)
        br['{}'.format(self.login)] = self.user
        br['{}'.format(self.psswd)] = password
        br.submit()
        response = br.response()
        print "[+] [User:{} Pass:{}] = {}".format(self.user, password, response.geturl())
        print

    def form_bruter(self):
        print
        try:
            self.login = raw_input("[+] Enter the input name of the username box: ")
            self.psswd = raw_input("[+] Enter the input name of the password box: ")
            self.user = raw_input("[+] Enter the username to brute-force the formulary: ")
            input_file = open(self.wordlist)
            try:
                for i in input_file.readlines():
                    password = i.strip("\n")
                    self.form_attempt(password)
            except KeyboardInterrupt:
                return
        except Exception as e:
            print "[!] Exception caught, check the fields according to the HTML page, Error: {}".format(e)

    def dir_bruter(self, word_queue, extensions=None):
        while not self.word_queue.empty():
            attempt = self.word_queue.get()
            attempt_list = []
            attempt_list.append("%s" % attempt)
            if "." not in attempt:
                attempt_list.append("%s/" % attempt)
            else:
                attempt_list.append("%s" % attempt)
            if extensions:
                for extension in extensions:
                    attempt_list.append("%s%s" % (attempt, extension))

            try:
                for brute in attempt_list:
                    url = "%s%s" % (self.target_url, urllib.quote(brute))

                    try:
                        headers = {}
                        headers["User-Agent"] = self.user_agent
                        r = urllib2.Request(url, headers=headers)
                        response = urllib2.urlopen(r)
                        if len(response.read()):
                            print "[%d] ==> %s" % (response.code, url)
                    except urllib2.URLError, e:
                        if e.code != 404:
                            print "!!! %d => %s" % (e.code, url)
                        pass
            except KeyboardInterrupt:
                break

    def start(self, mode, target, file):
        self.target_url = target
        self.wordlist = file
        self.threads = 5
        self.resume = None
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefor/19.0"
        self.word_queue = self.build_wordlist(self.wordlist)
        self.extensions = [".txt", ".php", ".bak", ".orig", ".inc", ".doc"]
        self.line = "\n------------------------------------------------------------------------\n"
        if mode == 'url':
            print "[+] Content URL bruter initialized."
            try:
                self.dir_bruter(self.word_queue, self.extensions, )
            except KeyboardInterrupt:
                print "[*] User requested shutdown."

        elif mode == 'form':
            print "[+] Brute-Form authentication initialized."
            try:
                self.form_bruter()
            except KeyboardInterrupt:
                print "[*] User requested shutdown."

    def stop(self, mode):
        if mode == 'url':
            try:
                print "[-] Content URL bruter finalized."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)

        elif mode == 'form':
            try:
                print "[-] Brute-Form authentication finalized."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)



class SSHbrutus(object):
    """SSH brute force class. """
    name = "SSH Brute-forcer"
    desc = "Perform password brute-force on SSH"
    version = "0.1"

    def __init__(self):
        self.trgt = None
        self.usr = None
        self.fobj = None

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

    def start(self, trgt, usr, fobj):
        self.trgt = trgt
        self.usr = usr
        self.fobj = fobj
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

brute_help = """\n
[Help] Brute-Force attacks, good luck padawan.
[Required] File as password wordlist and target as URL or IP.
parameters:
 - ssh
 - form
 - url
 - hash
example:
pythem> brute ssh help
\n"""

brute_ssh_help = """\n
[Help] SSH Brute-Force
[Required] IP address as target.
example:
pythem> set file wordlist.txt
pythem> set target 192.168.1.5
pythem> brute ssh
\n"""

brute_form_help = """\n
[Help] Formulary Brute-Force
[Required] URL (with http:// or https://) as target
example:
pythem> set file wordlist.txt
pythem> set target http://testphp.vulnweb.com/login.php
pythem> brute form
\n"""

brute_url_help = """\n
[Help] URL Brute-Force
[Required] URL (with http:// or https://) as target
example:
pythem> set file wordlist.txt
pythem> set target http://testphp.vulnweb.com/products.php?id=
pythem> brute url
\n"""

brute_hash_help = """\n
[Help] Hash Brute-Force
[Optional]File as wordlist, hash as target.
example:
pythem> set file wordlist.txt
pythem> set target 35f5de5eb59e2ac7f73d5821f9f2e4f6
pythem> brute hash
\n"""
