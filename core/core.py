#!/usr/bin/env python2.7
#coding=UTF-8

from scapy.all import *
from modules.utils import *
from modules.banners import *
from brain import Jarvis
import os

class Processor(object):

	def __init__(self, version):
		self.version = version
		self.arpmode = "rep"
		self.Jarvis = Jarvis()

	def start(self):
		try:
			while 1:
				self.command = raw_input("pythem> ")
				self.argv = self.command.split()
				self.input_list = [str(a) for a in self.argv]
				try:


					if self.command == "help":
						print_help(self.version)

					elif self.command == "jarvis-help":
						jarvis_help("0.0.5")

					elif self.command == "jarvis":
						self.Jarvis.start('core/start.py')

					elif self.command == "exit" or self.command == "quit":
						exit()

					elif self.input_list[0] == "set" or self.input_list[0] == "SET":
						if self.input_list[1] == "interface":
							try:
								self.interface = raw_input("[+] Enter the interface: ")
							except KeyboardInterrupt:
								pass
						elif self.input_list[1] == "gateway":
							try:
								self.gateway = raw_input("[+] Enter the gateway: ")
							except KeyboardInterrupt:
								pass
						elif self.input_list[1] == "target":
							try:
								self.targets = raw_input("[+] Enter the target(s): ")
							except KeyboardInterrupt:
								pass
						elif self.input_list[1] == "file":
							try:
								self.file = raw_input("[+] Enter the path to the file: ")
							except KeyboardInterrupt:
								pass
						elif self.input_list[1] == "arpmode":
							try:
								self.arpmode = raw_input("[+] Enter the arpmode:")
							except KeyboardInterrupt:
								pass


					elif self.command == "scan":
						print "[*] Select one scan mode, options = tcp/arp/manual"
						mode = raw_input("[+] Scan mode: ")
						if self.targets is not None and self.interface is not None:
							try:
								from modules.scanner import Scanner
								self.scan = Scanner(self.targets, self.interface, mode)
								self.scan.start()
							except KeyboardInterrupt:
								pass
						else:
							print "[!] You probably forgot to set the interface or a valid IP address/range"


					elif self.input_list[0] == "arpspoof":
                                        	try:
							myip = get_myip(self.interface)
                                                	mymac = get_mymac(self.interface)
                                                	from modules.arpoisoner import ARPspoof
							self.spoof = ARPspoof(self.gateway, self.targets, self.interface,self.arpmode ,myip, mymac)

							if self.input_list[1] == "start":
								self.spoof.start()
								print "[+] ARP spoofing initialized."

							elif self.input_list[1] == "stop":
								self.spoof.stop()
								print "[+] ARP spoofing finalized."

							else:
								print "[!] You probably forgot to type start or stop after arpspoof."
						except Exception as e:
							print "[!] Exception caught: {}".format(e)

					elif self.input_list[0] == "dnsspoof":
						try:

							if self.input_list[1] == "start":
								domain = raw_input("[+] Domain to be spoofed: ")
								redirect = raw_input("[+] IP address to be redirected: ")
								from modules.dnspoisoner import DNSspoof
								self.dnsspoof = DNSspoof(domain, redirect)
								self.dnsspoof.start()
								print "[+] DNS spoofing initialized"

							elif self.input_list[1] == "stop":
								self.dnsspoof.stop()
								print "[+] DNS spoofing finalized"
							else:
								print "[!] You probably forgot to type start or stop after dnsspoof."
						except Exception as e:
							print "[!] Exception caught: {}".format(e)

					elif self.command == "sniff":
						filter = raw_input("[+] Enter the filter: ")
						try:
							from modules.sniffer import Sniffer
                                                        self.sniff = Sniffer(self.interface, filter)
                                                        self.sniff.start()
						except KeyboardInterrupt:
                                                		pass


					elif self.command == "pforensic":
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


					elif self.command == "cookiedecode":
						try:
							cookiedecode()
						except KeyboardInterrupt:
							pass
						except Exception as e:
							print "[!] Exception caught: {}".format(e)
							pass



					elif self.input_list[0] == "decode":
						try:
							print decode(self.input_list[1])
						except KeyboardInterrupt:
							pass


					elif self.input_list[0] == "encode":
						try:
							print encode(self.input_list[1])
						except KeyboardInterrupt:
							pass


					elif self.command == "geoip":
						if self.targets is not None:
							try:
								from modules.geoip import Geoip
								path = "config/GeoLiteCity.dat"
								iptracker = Geoip(self.targets,path)
							except Exception as e:
								print "[!] Exception caught: {}".format(e)
								pass

					elif self.input_list[0] == "brute-force":
							if self.input_list[1] == "ssh":
								try:
									username = raw_input("[+] Enter the username to bruteforce: ")
									from modules.ssh_bruter import SSHbrutus
									brutus = SSHbrutus(self.targets, username, self.file)
									brutus.start()
                                                		except KeyboardInterrupt:
                                                        		brutus.stop()
									pass
                                                		except TypeError:
                                                        		print "[!] You probably forgot to set the wordlist file path."
                                                       			pass
							elif self.input_list[1] == "url":
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
							elif self.input_list[1] == "webform":
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
							else:
								print "[!] Select a valid type of brute-force type help to check."
					else:
						try:
							os.system("{}".format(self.command))
							pass
						except Exception as e:
							print "[!] Select a valid option, type help to check sintax."
							pass
				except IndexError:
					pass

				except Exception as e:
					print "Exception caught: {}".format(e)



		except KeyboardInterrupt:
			print "\n[*] User requested shutdown."
			exit()


