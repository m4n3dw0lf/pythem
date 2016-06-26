#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
#
# This file is part of the program Jarvis
#
# Jarvis is free software; you can redistribute it and/or
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


import praw
from brain import Jarvis

class RedditNews(object):

	def __init__(self):
		self.Jarvis = Jarvis()

	def Say(self, text):
		self.result = text.encode('ascii','ignore')
		self.Jarvis.Say(self.result)
		self.Jarvis.Say(" ")

	def get_headlines(self, limit=10):
	    	self.r = praw.Reddit(user_agent="Lyndon's news reader  by /u/LyndonArmitage")
	    	self.subs = self.r.get_subreddit("worldnews").get_hot(limit=limit)
		self.headlines = []
	    	for sub in self.subs:
    	    		self.headlines.append(sub.title)
   	    	self.first = " ".join(self.headlines)
   	    	self.news = self.first.replace(".", ". \n\n\n\n")
    	    	self.news.encode('ascii', 'ignore')
    	    	return self.news

	def speak_headlines(self, news=[]):
    		try:
			print self.news
    			self.Say(news)
		except KeyboardInterrupt:
			print "\n[*] User requested shutdown"
			Jarvis.Say("See you soon sir")
			exit()
		except Exception as e:
			print "[!] Exception caught: {}".format(e)
