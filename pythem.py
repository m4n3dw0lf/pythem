#!/usr/bin/env python2.7
#coding=UTF-8

from core.core import Processor
import os
import sys

version = "0.3.0"
Processor = Processor(version)

if os.geteuid() != 0:
	sys.exit("[-] Only for roots kid!")

if __name__ == '__main__':
	try:
		Processor.start()
	except Exception as e:
		print "Exception caught: {}".format(e)
