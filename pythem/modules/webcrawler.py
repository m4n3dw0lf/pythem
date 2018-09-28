#!/usr/bin/python2.7

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

reload(sys)
sys.setdefaultencoding('utf-8')

import urllib2
import re


class WebCrawler(object):

    def __init__(self):
        self.links = []
        self.status = {}
        self.port = None
        self.url = None

    def findNewLinks(self, data, saved_url):
        if ":" in self.url.split("://")[1]:
            if "/" not in self.url.split("://")[1]:
                self.port = self.url.split("://")[1].split(":")[1]
            elif "/" in self.url.split("://")[1]:
                self.port = self.url.split("://")[1].split(":")[1].split("/")[0]
            else:
                self.port = None
        else:
            self.port = None

        new_links = re.findall(r'href=[\'"]?([^\'" >]+)', data)
        new_links += re.findall(r'src=[\'"]?([^\'" >]+)', data)
        endext = [".css", ".png", ".ico", ".jpeg", ".jpg", ".mpg", ".mpeg", ".mp3", "#", ".gif"]
        startext = ["#", "//"]
        weird_strings = [";", ":"]

        for l in new_links:
            if l.endswith(tuple(endext)) or l.startswith(tuple(startext)) or any(x in l for x in weird_strings):
                continue

            elif l.startswith("/"):
                if self.port:
                    scheme = self.url.split("://")[0] + "://"
                    address = self.url.split("://")[1]
                    address = address.split(":")[0]
                    link = "{}{}:{}{}".format(scheme, address, self.port, l)
                else:
                    link = "{}{}".format(self.url, l)
                if link in self.links:
                    continue
                else:
                    self.links.append(link)

            elif not l.startswith("h"):
                address = saved_url.split("/")
                address = "/".join(address[:-1])
                link = "{}/{}".format(address, l)
                if link in self.links:
                    continue
                else:
                    self.links.append(link)
            else:
                link = l
                if link in self.links:
                    continue
                else:
                    self.links.append(link)

    def start(self, target):
        # try:
        global links
        self.links = []
        self.url = target
        try:
            host = self.url.split("://")[1].split(":")[0]
        except:
            host = self.url.split("://")[1]
        host = self.url.split("://")[0] + "://" + host
        website = urllib2.urlopen(self.url, timeout=1)
        html = website.read()
        self.findNewLinks(html, self.url)
        new_links = []
        buf = "Scope: {}\r\n".format(self.url)
        message = None

        while self.links != new_links:
            if len(self.links) > 100:
                message = "\nLimit of 100 links reached, breaking to avoid loops.\n"
            for l in self.links:
                # url = l
                try:
                    if l.startswith(host):
                        new_r = urllib2.urlopen(l, timeout=1)
                        self.status[l] = website.getcode()
                        new_html = new_r.read()
                        self.findNewLinks(new_html, l)
                    else:
                        self.status[l] = "external"
                        continue
                except Exception as e:
                    try:
                        self.status[l] = e.getcode()
                    except:
                        print "Exception caught: {}".format(e)
                    continue
            new_links = self.links

        for l in self.links:
            try:
                buf += "Link found: {} [{}]\r\n".format(l, self.status[l])
            except:
                pass

        if message:
            buf += message
        print buf
        # except Exception as e:
        #  print "Exception caught 2: {}".format(e)
