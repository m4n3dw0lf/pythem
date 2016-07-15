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

from core.interface import Processor
import os
import sys
import readline
readline.parse_and_bind('tab:complete')

version = "0.3.5"
Processor = Processor(version)

if os.geteuid() != 0:
	sys.exit("[-] Only for roots kid!")

if __name__ == '__main__':
	try:
		Processor.start()
	except Exception as e:
		print "Exception caught: {}".format(e)
