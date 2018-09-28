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

import sys
from subprocess import *
import time
import readline


class Completer(object):
    name = "TAB completer"
    desc = "Auto complete pythem commands with tab"
    version = "0.5"

    def __init__(self, path, console):
        tab = readline.parse_and_bind("tab: complete")
        if console == "pythem":
            historyPath = ".pythem_history".format(path)
            readline.read_history_file(historyPath)
            completer = readline.set_completer(self.pythem)
            # readline.write_history_file(historyPath)

        if console == "xploit":
            completer = readline.set_completer(self.xploit)

    def suboption(self, text, state):
        # print text
        # print state
        results = [x for x in self.suboptions if x.startswith(text)] + [None]
        return results[state]

    def xploit(self, text, state):
        self.words = ['clear', 'help', 'quit', 'disassemble', 'print', 'display', 'undisplay', 'enable', 'disable',
                      'run', 'continue', 'finish', 'step', 'next', 'backtrace', 'where', 'break', 'return', 'jump',
                      'set', 'info',
                      'handle', 'watch', 'whatis', 'frame', 'fuzz', 'cheatsheet', 'xploit', 'search', 'shellcode',
                      'encoder', 'decoder', 'decode', 'encode']
        results = [x for x in self.words if x.startswith(text)] + [None]
        return results[state]

    def pythem(self, text, state):
        # print text
        # print state
        if "set" in text and state == 1:
            self.suboptions = ['interface', 'target', 'gateway', 'file', 'domain', 'port', 'script', 'help']
            completer = readline.set_completer(self.suboption)

        elif "print" in text and state == 1:
            self.suboptions = ['interface', 'target', 'gateway', 'file', 'domain', 'port', 'script', 'help']
            completer = readline.set_completer(self.suboption)

        elif "scan" in text and state == 1:
            self.suboptions = ['tcp', 'arp', 'manual', 'help']
            completer = readline.set_completer(self.suboption)

        elif "arpspoof" in text and state == 1:
            self.suboptions = ['start', 'stop', 'status', 'help']
            completer = readline.set_completer(self.suboption)

        elif "dnsspoof" in text and state == 1:
            self.suboptions = ['start', 'stop', 'status', 'help']
            completer = readline.set_completer(self.suboption)

        elif "dhcpspoof" in text and state == 1:
            self.suboptions = ['start', 'stop', 'status', 'help']
            completer = readline.set_completer(self.suboption)

        elif "redirect" in text and state == 1:
            self.suboptions = ['start', 'stop', 'status', 'help']
            completer = readline.set_completer(self.suboption)

        elif "xploit" in text and state == 1:
            self.suboptions = ['stdin', 'tcp', 'help']
            completer = readline.set_completer(self.suboption)

        elif "brute" in text and state == 1:
            self.suboptions = ['ssh', 'url', 'form', 'help', 'hash']
            completer = readline.set_completer(self.suboption)

        elif "dos" in text and state == 1:
            self.suboptions = ['dnsdrop', 'dnsamplification', 'synflood', 'udpflood', 'icmpsmurf', 'icmpflood',
                               'dhcpstarvation', 'teardrop', 'pingofdeath', 'land', 'httpflood', 'help']
            completer = readline.set_completer(self.suboption)

        elif "sniff" in text and state == 1:
            self.suboptions = ['help']
            completer = readline.set_completer(self.suboption)

        elif "pforensic" in text and state == 1:
            self.suboptions = ['help']
            completer = readline.set_completer(self.suboption)

        elif "webcrawl" in text and state == 1:
            self.suboptions = ['help', 'start']
            completer = readline.set_completer(self.suboption)

        else:
            self.words = ['clear', 'help', 'exit', 'quit', 'set', 'print', 'scan', 'arpspoof', 'dnsspoof', 'redirect',
                          'sniff', 'pforensic', 'dos', 'xploit', 'brute', 'decode', 'encode', 'cookiedecode',
                          'dhcpspoof', 'webcrawl']
            results = [x for x in self.words if x.startswith(text)] + [None]
            return results[state]
