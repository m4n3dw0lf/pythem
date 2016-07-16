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

import os
import sys
import socket
import fcntl
import struct
import urllib
import base64
import termcolor


def decode(base):
        text = raw_input("[*] String to be decoded: ")
        decode = text.decode('{}'.format(base))
	result = "[+] Result: {}".format(decode)
	return result

def encode(base):
        text = raw_input("[*] String to be encoded: ")
	encode = text.encode('{}'.format(base))
	result = "[+] Result: {}".format(encode)
	return result

def cookiedecode():
	cookie = raw_input("[+] Enter the cookie value: ")
	res = base64.b64decode(urllib.unquote(cookie))
	print
	print res

def get_myip(interface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,
		struct.pack('256s', interface[:15])
	)[20:24])


def get_mymac(interface):
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
    	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]		


def set_ip_forwarding(value):
	with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
		file.write(str(value))
		file.close()
		print "[*] Setting the packet forwarding."
def iptables():
	os.system('iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
	print "[*] Iptables redefined"


def module_check(module):
	confirm = raw_input("[-] Do you checked if your system has [%s] installed?, do you like to try installing? (apt-get install %s will be executed if yes [y/n]: " % (modules,module))
	if confirm == 'y':
		os.system('apt-get install %s' % module)
	else:
		print "[-] Terminated"
		sys.exit(1)

def blue(message):
	blue_message = termcolor.colored(str(message),"blue", attrs=["bold"])
	return blue_message

def red(message):
	red_message = termcolor.colored(str(message), "red", attrs=["bold"])
	return red_message

def yellow(message):
	yellow_message = termcolor.colored(str(message), "yellow", attrs=["bold"])
	return yellow_message

def green(message):
	green_message = termcolor.colored(str(message), "green", attrs=["bold"])
	return green_message

def grey(message):
	grey_message = termcolor.colored(str(message), "grey", attrs=["bold"])
	return grey_message

def jarvis_help(version):
	print
	print blue("[ Jarvis - Personal Assistence - v{} ]".format(version))
	print
	print
	print blue("[*] exit |or| quit : 		Terminate the program.")
	print
	print
	print blue("[*] sleep |or| stop |or| wait:  	Sleep until you say 'Jarvis'.")
	print
	print
	print blue("[*] newspaper |or| news: 		Read the top trending news from reddit.")
	print
	print
	print blue("[*] say |or| speak [message]:     Ask Jarvis to say something.")
	print
	print green(" examples(say):")
	print
  	print green("  say I like donuts")
  	print green("  speak my name is Jarvis")
	print
	print
	print blue("[*] run [script]:	 		Run .sh script that you place on the scripts folder with chmod +x")
	print
	print green(" example(say):")
	print
	print green("  run firewall		 	| Place a firewall.sh on the scripts folder and give execution privilege first.")
	print
	print
	print blue("[*] browser:		 	Ask Jarvis to start your default browser.")
	print
 	print green(" example(say):")
	print
  	print green("  browser")
	print
	print
	print blue("[*] terminal:		 	Ask Jarvis to open a gnome-terminal.")
	print
 	print green(" example(say):")
	print
  	print green("  terminal")
	print
	print
	print blue("[*] search [query]	 	Ask Jarvis to search query via google.")
	print
	print green(" example(say):")
	print
	print green("  search python programming.")
	print
	print
 	print blue("[*] input [keystroke]:   		Send a command to the Arduino Leonardo without entering editor mode.")
	print
        print red("          * ARDUINO LEONARDO REQUIRED *")
	print
	print yellow("voice commands: (Same as EDITOR MODE )")
	print
	print
	print blue("[*] editor: 			Start the editor mode.")
	print
	print red("          * ARDUINO LEONARDO REQUIRED *")
	print
	print red("               [EDITOR MODE]")
	print
	print yellow("voice commands: (anything else will be typed)")
	print
	print green(" forward   = tab")
 	print green(" back      = (shift+tab)")
 	print green(" up        = up arrow")
	print green(" down      = down arrow")
	print green(" right     = right arrow")
	print green(" left      = left arrow")
	print green(" super     = super/windows")
	print green(" slash     = slash(/)")
	print green(" backspace = backspace(erase character)")
	print green(" erase	  = press backspace 10 times")
	print green(" space     = space(spacebar)")
	print green(" enter     = enter(return)")
	print green(" close	  = close(alt+f4)")
	print green(" escape    = escape(esc)")
	print green(" exit	  = leaves editor mode")
	print
	print


def banner(version):
	banner = """\n

              ---_ ...... _/_ -
             /  .      ./ .'*  '
             |''         /_|-'  '.
            /                     )
          _/                  >   '
        /   .   .       _.-" /  .'
        \           __/"     /.'
          \ '--  .-" /     / /'
           \|  \ | /     / /
                \:     / /
             `\/     / /
              \__`\/ /
                  \_|



[ PytheM - Penetration Testing Framework v{} ]\n
""".format(version)
	return blue(banner)


def print_help():
	print
	print blue("[*] help:			Print the help message.")
	print
	print
	print blue("[*] exit/quit:		Leave the program.")
	print
	print
	print blue("[*] set			Set a variable's value.")
	print
	print red(" parameters:")
	print
 	print yellow("  - interface")
 	print yellow("  - gateway")
 	print yellow("  - target")
 	print yellow("  - file")
 	print yellow("  - arpmode")
	print
	print green(" examples:")
	print
   	print red("  pythem> ") + "set interface         | open input to set"
	print "     or"
   	print red("  pythem> ") + "set interface wlan0   | don't open input to set value."
	print
	print
	print blue("[*] print		Print a variable's value.")
	print
  	print green(" examples:")
	print
	print red("  pythem> ") + "print gateway"
	print
	print
	print grey("[SECTION - NETWORK AND MAN-IN-THE-MIDDLE]")
	print
	print
	print blue("[*] scan		Make a tcp/manualport/arp scan.")
	print
	print "Should be called after setting an interface and a target"
	print
	print green(" examples:")
	print red("  pythem> ") + "scan"
	print "     or"
   	print red("  pythem> ") + "scan tcp"
	print
	print
	print blue("[*] arpspoof		Start or stop an arpspoofing attack.")
	print
	print "Optional setting arpmode to select arpspoofing mode should be filled with rep or req"
	print "rep to spoof responses, req to spoof requests"
	print
	print red(" arguments:")
	print
	print yellow("  start")
 	print yellow("  stop")
	print
  	print green(" examples:")
	print
   	print red("  pythem> ") + "arpspoof start"
   	print red("  pythem> ") + "arspoof stop"
	print
	print
	print blue("[*] dnsspoof		Start a dnsspoofing attack.")
	print
	print "Should be called after an arpspoofing attack has been started"
	print
	print green(" examples:")
	print
   	print red("  pythem> ")+ "dnsspoof start"
   	print red("  pythem> ") + "dnsspoof stop"
	print
	print
	print blue("[*] sniff		Start sniffing packets.")
	print
	print "Should be called after setting an interface"
	print
  	print red(" sniff custom filters:")
	print
    	print yellow("  - http")
    	print yellow("  - dns")
	print
  	print green(" examples:")
	print
   	print red("  pythem> ")+ 'sniff http'
	print "     or"
   	print red("  pythem> ")+ 'sniff'
   	print "  [+] Enter the filter: port 1337 and host 10.0.1.5  | tcpdump like format or http, dns specific filter."
	print
	print
	print blue("[*] pforensic		Start a packet-analyzer")
	print
	print "Should be called after setting an interface and a file with a .pcap file"
	print
  	print green(" examples:")
	print
   	print red("  pythem> ") + 'pforensic'
	print
   	print yellow("  pforensic> ") + 'help'
	print
	print
	print grey("[SECTION - EXPLOIT DEVELOPMENT AND REVERSE ENGINERING]")
	print
	print
	print blue("[*] xploit		Interactive stdin or tcp exploit development shell.")
	print
	print "The stdin should be called after setting file"
	print "The tcp should be called after setting target"
	print
	print red(" arguments:")
	print yellow("  stdin		| set file before")
 	print yellow("  tcp		| set target before")
	print
  	print green(" examples:")
	print
   	print red("  pythem> ") + "set file ./exec"
	print
   	print red("  pythem> ") + "xploit stdin"
        print "     or"
   	print red("  pythem> ") + "xploit"
   	print "  [*] Select one xploit mode, options = stdin/tcp"
   	print "  [+] Exploit mode: stdin"
	print blue("  xploit> ") + "help"
	print
	print
	print grey("[SECTION - BRUTE-FORCE]")
	print
	print
	print blue("[*] brute-force		Start a brute-force attack.")
	print
	print "Should be called after setting a target and a wordlist file path"
	print
	print red(" arguments:")
	print
	print yellow("  ssh		| ip address as target")
	print yellow("  url		| url (with http:// or https://) as target")
 	print yellow("  webform		| url (with http:// or https://) as target")
	print
  	print green(" examples:")
	print
   	print red("  pythem> ") + "brute-force webform"
   	print red("  pythem> ") + "brute-force ssh"
	print
	print
	print grey("[SECTION - UTILS]")
	print
	print blue("[*] geoip		Approximately geolocate the location of a IP address.")
	print
	print "Should be called after setting target(ip address)"
	print
	print green(" examples:")
	print
   	print red("  pythem> ") + "geoip"
	print "     or"
   	print red("  pythem> ") + "geoip 8.8.8.8"
	print
	print
	print blue("[*] decode and encode	Decode or encode a string with a chosen pattern.")
	print
	print green(" examples:")
	print
	print red("  pythem> ") + "decode base64"
   	print red("  pythem> ") + "encode ascii"
	print
	print
	print blue("[*] cookiedecode	Decode a base64 url encoded cookie value.")
	print
	print green(" example:")
	print
	print red("  pythem> ") + "cookiedecode"
	print
	print
	print yellow("* Anything else will be executed in the terminal like cd, ls, nano, cat, etc. *")
	print
	print
	print grey("(+) Call the voice-controlled assistant Jarvis")
	print
	print green("link:") + blue(" https://github.com/m4n3dw0lf/Jarvis")
	print
	print
	print blue("[*] jarvis")
	print
	print red("type jarvis-help to see the jarvis help page.")
	print
	print green(" examples:")
	print
	print red("  pythem> ")+ "jarvis	 (Call Jarvis in speech recognition mode)"
	print
   	print red("  pythem> ")+ "jarvis-help    (Print the Jarvis help message)"
	print
   	print red("  pythem> ")+ "jarvis-log     (Check the Jarvis log)"
	print "     or"
   	print red("  pythem> ")+ "jarvis-log err"
	print
   	print red("  pythem> ") + "jarvis-say    (Ask Jarvis to say something)"
	print "     or"
   	print red("  pythem> ") + "jarvis-say hello my name is Jarvis."
	print
   	print red("  pythem> ") + "jarvis-read 	 (If no file is specified, should be called after setting file.)"
   	print "     or"
   	print red("  pythem> ") + "jarvis-read file.txt"
	print
	print red("by: ") + blue("m4n3dw0lf")

