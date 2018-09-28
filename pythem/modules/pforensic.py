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

from scapy.all import *
import sys
import os
import termcolor
from utils import color


class PcapReader(object):
    name = "Simple pcap analyzer"
    desc = "Use some functions to analyze a pcap file"
    version = "0.3"
    obs = "need to filter for images and decode encoded gzip content"

    def __init__(self, file):
        try:
            self.file = file
            self.packets = rdpcap(file)
        except:
            if file == "pythem_module_test":
                return
            print "You probably forgot to set a file to be analyzed."

    def printHelp(self):
        print
        print color("   [ pythem - Forensic pcap reader ]", "grey")
        print
        print color("   FILE - [ {} ]".format(self.file), "red")
        print
        print
        print color("[*] help:                          Print the help message", "blue")
        print
        print
        print color("[*] clear:                 Clean the screen, same as GNU/Linux OS 'clear'", "blue")
        print
        print
        print color("[*] exit/quit:                     Return to pythem", "blue")
        print
        print
        print color("[*] show:                  Display all the packets and their index numbers.", "blue")
        print
        print
        print color(
            "[*] conversations:         Display pictogram with conversations between hosts from the analyzed file.",
            "blue")
        print
        print
        print color("[*] filter <string/layer>: Run a custom filter in the packets.", "blue")
        print
        print
        print color("[*] packetdisplay [num]:   Display the full content of index selected packet.", "blue")
        print
        print
        print color("[*] count :                Display how much packets the .pcap file have.", "blue")

    def custom_filter(self, packets, filter):
        x = 0
        if filter == "string":
            from StringIO import StringIO

            try:
                find = raw_input("[+] String to search on packets (case sensitive): ")
                for p in packets:
                    capture = StringIO()
                    save_stdout = sys.stdout
                    sys.stdout = capture
                    p.show()
                    sys.stdout = save_stdout
                    pkt = "\r\n\n\n------------------------[Packet n:{}]------------------------\r\n".format(x)
                    end = "\r\n------------------------------------------------------------\r\n"

                    if find in capture.getvalue():
                        print pkt
                        p.show()
                        print end

                    x += 1
            except KeyboardInterrupt:
                print "[-] User requested shutdown."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)

        elif filter == "layer":
            try:
                find = raw_input("[+] Layer to search on packets (uppercase): ")
                for p in packets:
                    pkt = "\r\n\n\n------------------------[Packet n:{}]------------------------\r\n".format(x)
                    end = "\r\n------------------------------------------------------------\r\n"
                    if p.haslayer(find):
                        print pkt
                        p.show()
                        print end

                    x += 1
            except KeyboardInterrupt:
                print "[-] User requested shutdown."
            except Exception as e:
                print "[!] Exception caught: {}".format(e)


        else:
            print "[-] Select a valid filter: 'string' or 'layer'"
            return

    def start(self):
        while True:
            try:
                console = termcolor.colored("pforensic>", "yellow", attrs=["bold"])
                self.command = raw_input("{} ".format(console))
                self.argv = self.command.split()
                self.input_list = [str(a) for a in self.argv]

                try:
                    if self.input_list[0] == 'packetdisplay':
                        try:
                            self.packets[int(self.input_list[1])].show()
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "filter":
                        try:
                            self.filter = self.input_list[1]
                            self.custom_filter(self.packets, self.filter)
                        except IndexError:
                            print "[!] Select a option to filter, string or layer"
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == 'packetload':
                        try:
                            print "[+] Packet {} payload: ".format(self.input_list[1])
                            self.filter_lookup(self.packets[int(self.input_list[1])])

                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == 'exit':
                        break
                    elif self.input_list[0] == 'quit':
                        break
                    elif self.input_list[0] == 'help':
                        self.printHelp()
                    elif self.input_list[0] == 'clear':
                        os.system('clear')
                    elif self.input_list[0] == 'ls':
                        os.system('ls')
                    elif self.input_list[0] == 'summary':
                        try:
                            self.packets.summary()
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                    elif self.input_list[0] == 'show':
                        try:
                            self.packets.show()
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                    elif self.input_list[0] == 'count':
                        try:
                            print "[+] Number of packets: {}".format(len(self.packets))
                        except  Exception as e:
                            print "[!] Exception caught: {}".format(e)
                    elif self.input_list[0] == 'conversations':
                        try:
                            self.packets.conversations()
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                    else:
                        print "[-] Select a valid option."

                except IndexError:
                    pass
            except KeyboardInterrupt:
                break
