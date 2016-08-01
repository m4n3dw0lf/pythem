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
from core.interface import Processor
from modules.utils import banner

version = "0.4.0"
Processor = Processor()

'''
Function os.getuid() returns ID of a user who runs your program. 
Function os.geteuid() of a user your program use permissions of. 

 Normally `os.geteuid()` & `os.getuid()` returns the same uid.
 There are a few other cases where the UID and EUID won't match, but they're not too common. 
'''
# 用这个可以判断是否是root用户
if os.geteuid() != 0:
	sys.exit("[-] Only for roots kido! ")

if __name__ == '__main__':
	try:
		print banner(version)
		Processor.start()
	except Exception as e:
		print "[!] Exception caught: {}".format(e)
