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

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import os, sys
import termcolor
import psutil

from pythem.modules.utils import *
from pythem.modules.dos import *
from pythem.modules.sniffer import *
from pythem.modules.pforensic import *
from pythem.modules.scanner import *
from pythem.modules.webcrawler import *
from pythem.modules.arpoisoner import *
from pythem.modules.dnspoisoner import *
from pythem.modules.redirect import *
from pythem.modules.dhcpoisoner import *
from pythem.modules.xploit import *
from pythem.modules.bruteforcer import *
from pythem.modules.completer import Completer


def save_command_history(cmd):
    try:
        with open(".pythem_history", "a+") as hist_file:
            hist_file.write("{}\n".format(cmd))
    except Exception as e:
        print "[!] Exception caught: {} ".format(e)
        pass


class Processor(object):
    name = "Interface-Processor"
    desc = "Console to process commands"
    version = "1.7"

    def __init__(self):
        # Script path
        self.path = os.path.abspath(os.path.dirname(sys.argv[0]))

        # Variables
        self.targets = None
        self.file = None
        self.interface = None
        self.gateway = None
        self.port = 80
        self.domain = None
        self.redirect = None
        self.script = None
        self.filter = None

        # Status
        self.arpspoof_status = False
        self.dnsspoof_status = False
        self.dhcpspoof_status = False
        self.redirect_status = False
        self.dnsdrop_status = 0
        self.dnsamplification_status = 0
        self.synflood_status = 0
        self.udpflood_status = 0
        self.dnsflood_status = 0
        self.pingofdeath_status = 0
        self.icmpflood_status = 0
        self.icmpsmurf_status = 0
        self.dhcpstarvation_status = 0
        self.teardrop_status = 0

    # Recursive "shell=True" process killing
    def pskill(self, proc_pid):
        process = psutil.Process(proc_pid)
        for proc in process.children(recursive=True):
            proc.kill()
        process.kill()

    # Main
    def start(self):
        try:
            # Create .pythem_history (if it does not exists, Completer will fail
            save_command_history("")
            # Untill break or CTRL+C
            while 1:
                # Call the object Completer code in modules/completer.py
                completer = Completer(self.path, "pythem")
                # Use termocolor import to set the default commandline red
                console = termcolor.colored("pythem>", "red", attrs=["bold"])
                # Iterable console shell commands with the while 1
                try:
                    self.command = raw_input("{} ".format(console))
                except EOFError:
                    self.command = "exit"
                save_command_history(self.command)
                # Separate the user input by spaces " ", can use like this too: self.input_list = [str(a) for a in self.argv]
                self.input_list = self.command.split()
                try:
                    # HELP
                    if self.command == "help":
                        print_help()
                    # EXIT
                    elif self.command == "exit" or self.command == "quit":
                        print "[*] User requested shutdown."
                        if self.dnsdrop_status == 1:
                            self.dos.dnsdropstop()
                        if self.arpspoof_status:
                            iptables()
                            set_ip_forwarding(0)
                        exit()
                    elif self.input_list[0] == "set" or self.input_list[0] == "SET":
                        try:
                            if self.input_list[1] == "interface":
                                try:
                                    self.interface = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.interface = raw_input("[+] Enter the interface: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "port":
                                try:
                                    self.port = int(self.input_list[2])
                                except IndexError:
                                    try:
                                        self.port = input("[+] Enter the default port: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "domain":
                                try:
                                    self.domain = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.domain = raw_input("[+] Domain to be spoofed: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "redirect":
                                try:
                                    self.redirect = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.redirect = raw_input("[+] IP address to redirect DNS queries: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "script":
                                try:
                                    self.script = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.script = raw_input("[+]Script url/path: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "gateway":
                                try:
                                    self.gateway = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.gateway = raw_input("[+] Enter the gateway: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "target":
                                try:
                                    self.targets = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.targets = raw_input("[+] Enter the target(s): ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "file":
                                try:
                                    self.file = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.file = raw_input("[+] Enter the path to the file: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "filter":
                                try:
                                    self.filter = self.input_list[2]
                                except IndexError:
                                    try:
                                        self.filter = raw_input("[+] Enter the sniffer filter: ")
                                    except KeyboardInterrupt:
                                        pass
                            elif self.input_list[1] == "help":
                                print "\n[Help] Select a variable to set."
                                print "parameters:"
                                print " - interface"
                                print " - gateway"
                                print " - target"
                                print " - file"
                                print " - domain"
                                print " - redirect"
                                print " - script"
                                print " - filter"
                                print "example:"
                                print "{} set interface\n".format(console)
                        except IndexError:
                            print "[!] Select a valid variable to set."

                    elif self.input_list[0] == "print":
                        try:
                            if self.input_list[1] == "interface":
                                print "[+] Network Interface: {}".format(self.interface)
                            elif self.input_list[1] == "port":
                                print "[+] Default port: {}".format(self.port)
                            elif self.input_list[1] == "domain":
                                print "[+] Domain: {}".format(self.domain)
                            elif self.input_list[1] == "redirect":
                                print "[+] Redirecting to: {}".format(self.redirect)
                            elif self.input_list[1] == "script":
                                print "[+] Script url/path: {}".format(self.script)
                            elif self.input_list[1] == "gateway":
                                print "[+] Gateway IP Address: {}".format(self.gateway)
                            elif self.input_list[1] == "target":
                                print "[+] Target(s): {}".format(self.targets)
                            elif self.input_list[1] == "file":
                                print "[+] File path: {}".format(self.file)
                            elif self.input_list[1] == "help":
                                print "\n[Help] Print a variable value."
                                print "example:"
                                print "{} print interface\n".format(console)
                        except IndexError:
                            print "[!] Select a valid variable name."

                    elif self.input_list[0] == "webcrawl":
                        if self.input_list[1] == "help":
                            print(webcrawler_help)
                            continue
                        elif self.input_list[1] == "start":
                            from pythem.modules.webcrawler import WebCrawler
                            self.webcrawl = WebCrawler()
                            try:
                                self.webcrawl.start(self.input_list[2])
                            except IndexError:
                                try:
                                    if self.targets:
                                        self.webcrawl.start(self.targets)
                                    else:
                                        self.targets = raw_input("[+] Enter the target URL: ")
                                        self.webcrawl.start(self.targets)
                                except KeyboardInterrupt:
                                    pass
                                except Exception as e:
                                    print "[!] Exception caught: {}".format(e)
                            except Exception as e:
                                print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "scan":
                        try:
                            if self.input_list[1] == "help":
                                print(scanner_help)
                                continue
                            mode = self.input_list[1]
                            if self.targets is not None and self.interface is not None:
                                from pythem.modules.scanner import Scanner
                                self.scan = Scanner()
                                self.scan.start(self.targets, self.interface, mode)
                            else:
                                print "[!] You probably forgot to set the interface or a valid IP address/range."
                        except IndexError:
                            try:
                                print "[*] Select one scan mode, options = tcp/arp/manual"
                                mode = raw_input("[+] Scan mode: ")
                            except KeyboardInterrupt:
                                pass
                                if self.targets is not None and self.interface is not None:
                                    from pythem.modules.scanner import Scanner
                                    self.scan = Scanner()
                                    self.scan.start(self.targets, self.interface, mode)
                                else:
                                    print "[!] You probably forgot to set the interface or a valid IP address/range."
                                    pass
                            except Exception as e:
                                print "[!] Exception caught: {}".format(e)
                                pass

                    elif self.input_list[0] == "arpspoof":
                        try:
                            if self.input_list[1] == "start":
                                myip = get_myip(self.interface)
                                mymac = get_mymac(self.interface)
                                self.arpspoof_status = True
                                self.spoof = ARPspoof()
                                self.spoof.start(self.gateway,self.targets,self.interface,myip,mymac)
                                print "[+] ARP spoofing initialized."
                            elif self.input_list[1] == "stop":
                                self.spoof.stop()
                                self.arpspoof_status = False
                                print "[+] ARP spoofing finalized."
                            elif self.input_list[1] == "status":
                                if self.arpspoof_status:
                                    stat = "running"
                                else:
                                    stat = "down"
                                    print "[*] ARP spoofing status: {}".format(stat)
                            elif self.input_list[1] == "help":
                                print(arpoisoner_help)
                                continue
                            else:
                                print "[!] Select a valid option, call help to check syntax."
                        except TypeError:
                            print "[!] You probably forgot to set interface or gateway."
                        except IndexError:
                            print "[!] You probably forgot to type start or stop after arpspoof."
                        except AttributeError:
                            pass
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "dhcpspoof":
                        try:
                            if self.input_list[1] == "start":
                                self.dhcpspoof_status = True
                                self.dhcpspoof = DHCPspoof()
                                self.dhcpspoof.start("silent")
                                print "[+] DHCP spoofing initialized."
                            elif self.input_list[1] == "stop":
                                print "[+] DHCP spoofing finalized."
                                exit(0)
                            elif self.input_list[1] == "status":
                                if self.dhcpspoof_status:
                                    stat = "running"
                                else:
                                    stat = "down"
                                    print "[*] DHCP spoofing status: {}".format(stat)
                            elif self.input_list[1] == "help":
                                print(dhcpoisoner_help)
                                continue
                            else:
                                print "[!] Select a valid option, call help to check syntax."
                        except IndexError:
                            print "[!] You probably forgot to type start, stop, status or help after dhcpspoof."
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "dnsspoof":
                        try:
                            if self.input_list[1] == "start":
                                if not self.arpspoof_status:
                                    print "[!] You probably forgot to start an ARP spoofing."
                                    continue
                                if self.domain:
                                    domain = self.domain
                                else:
                                    try:
                                        domain = raw_input(
                                            "[!] Type all to spoof all domains\n[+] Domain to be spoofed: ")
                                        self.domain = domain
                                    except KeyboardInterrupt:
                                        pass
                                if self.redirect:
                                    redirect = self.redirect
                                else:
                                    myip = get_myip(self.interface)
                                    opt = raw_input(
                                        "[+] Default address to redirect is:{} do you want to change?[y/n]".format(
                                            myip))
                                    if opt == "y" or opt == "Y" or opt == "yes" or opt == "YES":
                                        try:
                                            redirect = raw_input("[+] IP address to be redirected: ")
                                        except KeyboardInterrupt:
                                            pass
                                    else:
                                        redirect = myip
                                self.dnsspoof = DNSspoof()
                                self.dnsspoof.start(domain, None, redirect)
                                print "[+] DNS spoofing initialized"
                                self.dnsspoof_status = True

                            elif self.input_list[1] == "stop":
                                self.dnsspoof.stop()
                                self.dnsspoof_status = False
                                print "[+] DNS spoofing finalized"
                            elif self.input_list[1] == "status":
                                if self.dnsspoof_status:
                                    stat = "running"
                                else:
                                    stat = "down"
                                    print "[*] DNS spoofing status: {}".format(stat)
                            elif self.input_list[1] == "help":
                                print(dnspoisoner_help)
                                continue
                            else:
                                print "[!] Select a valid option, call help to check syntax."
                        except IndexError:
                            print "[!] You probably forgot to type start or stop after dnsspoof."
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "redirect":
                        try:
                            if self.input_list[1] == "start":
                                myip = get_myip(self.interface)
                                try:
                                    self.redirect = Redirect()
                                    self.redirect_status = True
                                    self.redirect.start(myip, self.port, self.script)
                                except AttributeError:
                                    print "\n[!] Select a valid script source path or url."
                                except Exception as e:
                                    print "[!] Exception caught: {}".format(e)
                            elif self.input_list[1] == "stop":
                                try:
                                    self.redirect.stop()
                                    self.redirect_status = False
                                except Exception as e:
                                    print "[!] Exception caught: {}".format(e)
                            elif self.input_list[1] == "status":
                                if self.redirect_status:
                                    stat = "running"
                                else:
                                    stat = "down"
                                    print "[*] Script redirect status: {}".format(stat)
                            elif self.input_list[1] == "help":
                                print(redirect_help)
                                continue
                            else:
                                print "[!] You need to specify  start, stop or status after the redirect module call."
                        except IndexError:
                            print "[!] You probably forgot to start or stop the redirect module."
                        except TypeError:
                            print "[!] You probably forgot to start an arpspoof attack ."
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "dos":
                        self.dos = DOSer()
                        try:
                            if self.input_list[1] == "dnsdrop":
                                try:
                                    if self.input_list[2] == "help":
                                        print(dnsdrop_help)
                                        continue
                                except IndexError:
                                    if self.arpspoof_status:
                                        try:
                                            myip = get_myip(self.interface)
                                            self.dos.dnsdropstart(myip)
                                            self.dnsdrop_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)
                                    else:
                                        print "[!] You need to start a arpspoof on a target (IP/Range) to start dnsdrop."

                            if self.input_list[1] == "httpflood":
                                try:
                                    if self.input_list[2] == "help":
                                        print(httpflood_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set an URL as target."
                                    else:
                                        try:
                                            self.dos.httpflood(self.targets)
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "dnsamplification":
                                try:
                                    if self.input_list[2] == "help":
                                        print(dnsamplification_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            self.dos.dnsamplificationstart(self.targets)
                                            self.dnsamplification_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "dhcpstarvation":
                                try:
                                    if self.input_list[2] == "help":
                                        print(dhcpstarvation_help)
                                        continue
                                except IndexError:
                                    try:
                                        self.dos.dhcpstarvationstart()
                                        self.dhcpstarvation_status = 1
                                    except TypeError:
                                        print "[!] You probably forgot to set a network interface."

                            elif self.input_list[1] == "land":
                                try:
                                    if self.input_list[2] == "help":
                                        print(land_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            self.dos.landstart(self.targets, self.port)
                                            self.land_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "pingofdeath":
                                try:
                                    if self.input_list[2] == "help":
                                        print(pingofdeath_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            self.dos.pingofdeathstart(self.targets)
                                            self.pingofdeath_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "udpflood":
                                try:
                                    if self.input_list[2] == "help":
                                        print(udpflood_help)
                                        continue
                                except IndexError:

                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            myip = get_myip(self.interface)
                                            self.dos.udpfloodstart(myip, self.targets, self.port)
                                            self.udpflood_status = 1
                                        except TypeError:
                                            print "[!] You probably forgot to set a network interface."

                            elif self.input_list[1] == "icmpflood":
                                try:
                                    if self.input_list[2] == "help":
                                        print(icmpflood_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            myip = get_myip(self.interface)
                                            self.dos.icmpfloodstart(myip, self.targets)
                                            self.icmpflood_status = 1
                                        except TypeError:
                                            print "[!] You probably forgot to set a network interface."

                            elif self.input_list[1] == "synflood":
                                try:
                                    if self.input_list[2] == "help":
                                        print(synflood_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            myip = get_myip(self.interface)
                                            self.dos.synfloodstart(myip, self.targets, self.port)
                                            self.synflood_status = 1
                                        except TypeError:
                                            print "[!] You probably forgot to set a network interface."

                            elif self.input_list[1] == "icmpsmurf":
                                try:
                                    if self.input_list[2] == "help":
                                        print(icmpsmurf_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            self.dos.icmpsmurfstart(self.targets)
                                            self.icmpsmurf_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "teardrop":
                                try:
                                    if self.input_list[2] == "help":
                                        print(teardrop_help)
                                        continue
                                except IndexError:
                                    if not self.targets:
                                        print "[!] You probably forgot to set a IP address as target."
                                    else:
                                        try:
                                            self.dos.teardrop(self.targets)
                                            self.teardrop_status = 1
                                        except Exception as e:
                                            print "[!] Exception caught: {}".format(e)

                            elif self.input_list[1] == "help":
                                print(dos_help)

                            else:
                                print"[!] Select a valid option, type help to check syntax."

                        except IndexError:
                            print "[!] You probably forgot to specify the type of DoS to use."

                    elif self.command == "sniff help":
                        if self.input_list[1] == "help":
                            print(sniff_help)
                            continue

                    elif self.input_list[0] == "sniff":
                        try:
                            hasfilter = self.input_list[1]
                            self.filter = " ".join(self.input_list[1:])
                            if self.filter == "dns":
                                self.filter = "port 53"
                                self.sniff = Sniffer()
                                print "\n[+] pythem sniffer initialized.\n"
                                self.sniff.start(self.interface, self.filter)

                        except IndexError:
                            try:
                                self.filter = raw_input("[+] Enter the filter(empty for core sniffer): ")
                                if self.filter == "dns":
                                    self.filter = "port 53"
                                if not self.filter:
                                    self.filter = None
                                self.sniff = Sniffer()
                                print "\n[+] pythem sniffer initialized.\n"
                                self.sniff.start(self.interface, self.filter)
                            except KeyboardInterrupt:
                                pass

                    elif self.input_list[0] == "pforensic":
                        try:
                            if self.input_list[1] == "help":
                                print(pforensic_help)
                                continue
                            else:
                                print "[!] Invalid option."
                        except IndexError:
                            try:
                                self.pcapread = PcapReader()
                                self.pcapread.start(self.file)
                            except KeyboardInterrupt:
                                pass
                            except TypeError:
                                print "[!] You probably forgot to set the .pcap file"
                                pass
                            except Exception as e:
                                print "[!] Exception caught: {}".format(e)
                                pass

                    elif self.input_list[0] == "xploit":
                        try:
                            from pythem.modules.xploit import Exploit
                            if len(self.input_list) > 1:
                                if self.input_list[1] == "help":
                                    print(xploit_help)
                                    continue
                            elif self.file:
                                self.xploit = Exploit()
                                self.xploit.start(self.file)
                            else:
                                self.xploit = Exploit()
                                self.xploit.start(None)
                        except KeyboardInterrupt:
                            pass
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                            pass

                    elif self.input_list[0] == "cookiedecode":
                        try:
                            try:
                                if self.input_list[1] == "help":
                                    print(cookiedecode_help)
                                    continue
                            except IndexError:
                                cookiedecode()
                        except KeyboardInterrupt:
                            pass
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                            pass

                    elif self.input_list[0] == "decode":
                        try:
                            if self.input_list[1] == "help":
                                print(decode_help)
                                continue
                        except IndexError:
                            try:
                                msg = raw_input("[+] Decode: ")
                                print decode(msg)
                            except KeyboardInterrupt:
                                pass
                            except Exception as e:
                                print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "encode":
                        try:
                            if self.input_list[1] == "help":
                                print(encode_help)
                                continue
                            print encode(self.input_list[1])
                        except IndexError:
                            try:
                                msg = raw_input("[+] Encode:")
                                print decode(msg)
                            except KeyboardInterrupt:
                                pass
                            except Exception as e:
                                print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "brute":
                        try:
                            if self.input_list[1] == "help":
                                print(brute_help)
                                continue

                            if self.input_list[1] == "hash":
                                try:
                                    if self.input_list[2] == "help":
                                        print(brute_hash_help)
                                        continue
                                    else:
                                        print "[!] Invalid option."
                                except IndexError:
                                    cracker = HashCracker()
                                    found = cracker.hashcrack(self.targets, self.file)
                                    if found: print found
                                except KeyboardInterrupt:
                                    pass

                            if self.input_list[1] == "ssh":
                                try:
                                    if self.input_list[2] == "help":
                                        print(brute_ssh_help)
                                        continue
                                    else:
                                        print "[!] Invalid option."
                                except IndexError:
                                    try:
                                        username = raw_input("[+] Enter the username to bruteforce: ")
                                        port = raw_input("[+] Enter SSH port (Enter for 22):")
                                        if not port:
                                            ssh_port = 22 
                                        else: 
                                            ssh_port = int(port)
                                        brutus = SSHbrutus()
                                        brutus.start(self.targets, username, self.file, ssh_port)
                                    except KeyboardInterrupt:
                                        pass
                                    except TypeError:
                                        print "[!] You probably forgot to set the wordlist file path."
                                        pass

                            elif self.input_list[1] == "url":
                                try:
                                    if self.input_list[2] == "help":
                                        print(brute_url_help)
                                        continue
                                    else:
                                        print "[!] Invalid option."

                                except IndexError:
                                    try:
                                        brutus = WEBbrutus()
                                        brutus.start('url',self.targets,self.file)
                                    except KeyboardInterrupt:
                                        brutus.stop('url')
                                        pass
                                    except TypeError:
                                        print "[!] You probably forgot to set the wordlist file path."
                                        pass

                            elif self.input_list[1] == "form":
                                try:
                                    if self.input_list[2] == "help":
                                        print(brute_form_help)
                                        continue
                                    else:
                                        print "[!] Invalid option."

                                except IndexError:
                                    try:
                                        brutus = WEBbrutus()
                                        brutus.start('form',self.targets,self.file)
                                    except KeyboardInterrupt:
                                        brutus.stop('form')
                                        pass
                                    except TypeError:
                                        print "[!] You probably forgot to set the wordlist file path."
                                        pass
                        except IndexError:
                            print "[!] Select a valid brute force type."
                    else:
                        try:
                            os.system("{}".format(self.command))
                            pass
                        except Exception as e:
                            print "[!] Select a valid option, type help to check syntax."
                            continue
                except IndexError:
                    pass

                except Exception as e:
                    print "[!] Exception caught: {}".format(e)

                except KeyboardInterrupt:
                    print "\n[*] User requested shutdown."
                    if self.dnsdrop_status == 1:
                        self.dos.dnsdropstop()
                    if self.arpspoof_status:
                        iptables()
                        set_ip_forwarding(0)
                    exit()

        except KeyboardInterrupt:
            print "\n[*] User requested shutdown."
            if self.dnsdrop_status == 1:
                self.dos.dnsdropstop()
            if self.arpspoof_status:
                iptables()
                set_ip_forwarding(0)
            exit()
