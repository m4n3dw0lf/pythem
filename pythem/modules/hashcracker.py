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


class HashCracker(object):

    def __init__(self, hash=None, wordlist=None):
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
        self.hashcrack()

    def hashcrack(self):
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


if __name__ == "__main__":
    HashCracker(argv[1], argv[2])
