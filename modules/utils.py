#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
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

def jarvis_help(version):
	print """\n
[ Jarvis - Personal Assistence - v{} ]

[*] exit:	 	Terminate the program.

[*] sleep:		Sleep untill you say "Jarvis"

[*] newspaper:		Read the top trending news from reddit.

[*] say [message]:      Ask Jarbas to say something.

 examples:

  say i like donnuts
  say my name is jarvis

[*] run [script]:	Run .sh script that you place on the scripts folder with chmod +x

 example:

  run firewall		| Place a firewall.sh on the scripts folder and give execution privilege first

[*] start [program]:	Ask Jarbas to start a program.

	* ARDUINO LEONARDO REQUIRED *

voice commands:

 browser   = start google-chrome browser
 terminal  = start a terminal

[*] editor: 		Start the editor mode.

	* ARDUINO LEONARDO REQUIRED *

	[EDITOR MODE]

voice commands: (anything else will be typed)

 forward   = tab
 back      = (shift+tab)
 up        = up arrow
 down      = down arrow
 right     = right arrow
 left      = left arrow
 super     = super/windows
 slash     = slash(/)
 backspace = backspace(erase character)
 erase	   = press backspace 10 times
 space     = space(spacebar)
 enter     = enter(return)
 close	   = close(alt+f4)
 escape    = escape(esc)

 exit	   = leaves editor mode\n""".format(version)


def print_help(version):
	print """\n

           ---_ ...... _/_ -
          /  .      ./ .'*\
          :''         /_|-'  \.
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


[ PytheM - Pentest/Network Framework v{} ]

[*] help:		Print this help message.


[*] exit/quit:		Leave the program.


[*] set			Set a parameter value.

parameters:

 interface
 gateway
 target
 file
 arpmode

  examples:

   pythem> set interface         |open input to set


[*] scan		Make a tcp/manualport/arp scan.

(Should be called after setting interface and target)

  examples:

   pythem> scan


[*] arpspoof		Start or stop a arpspoofing attack.

(Optional setting arpmode to select arpspoofing mode should be filled with rep or req) 
(rep to spoof responses, req to spoof requests)

arguments:

 start
 stop

  examples:
   arpspoof start
   arpspoof stop


[*] dnsspoof		Start a dnsspoofing attack.

(Should be called after a arpspoofing attack have been started)

  examples:

   pythem> dnsspoof start
   pythem> dnsspoof stop


[*] sniff		Start sniffing packets.

(Should be called after setting interface)

  examples:

   pythem> sniff
   [+] Enter the filter: port 1337 and host 10.0.1.5  | tcpdump like format

[*] pforensic		Start a packet-analyzer<br />

(Should be called after setting interface and file with a .pcap file)

  examples:

   pythem> pforensic
   pforensic> help

[*] brute-force		Start a brute-force attack.

(Should be called after setting target and wordlist file path)

arguments:

 ssh		| ip address as target
 url		| url (with http:// or https://) as target
 webform	| url (with http:// or https://)as target

  examples:

   pythem> brute-force webform
   pythem> brute-force ssh

[*] geoip		Geolocalizate approximately the location of a IP address.


(Should be called after setting target (Ip address))

  examples:

   pythem> geoip


[*] decode and encode	Decode or encode a string with choosen pattern

  examples:

   pythem> decode base64
   pythem> encode ascii


[*] cookiedecode	Decode a base64 url encoded cookie value.

  example:

   pythem> cookiedecode


* Anything else will be executed in the terminal like cd, ls, nano, cat, etc. *

(+) Call the voice-controlled assistant Jarvis

link: https://github.com/m4n3dw0lf/Jarvis

[*] jarvis

type jarvis-help to see the jarvis help page.

  examples:

   pythem> jarvis
   pythem> jarvis-help


by: m4n3dw0lf
""".format(version)
