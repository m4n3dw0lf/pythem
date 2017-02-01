#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016-2017 Angelo Moura
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

from pygeoip import pygeoip 
import os
import sys

class Geoip(object):

	name = "Geo localizator"
	desc = "Geo localizate IP addresses"
	version = "0.1"

	def __init__(self, target, path):
		self.target = target
		try:
			self.gip = pygeoip.GeoIP(path)
			self.search()
		except pygeoip.GeoIPError:
			print "[!] You probably forgot to set the target or give a invalid target as argument."
        	except Exception as e: 
        		print "[!] Exception caught: {}".format(e)

	def search(self):
		addr = self.target
		rec = self.gip.record_by_addr(addr)
		for key,val in rec.items():
			print "[~] %s: %s" %(key, val)
