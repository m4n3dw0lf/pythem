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


from brain import Jarvis
from randomizer import Randomstorm
from newspappers import RedditNews
import serial.tools.list_ports
import os

class Processor(object):

	def __init__(self):
		self.array = []
		self.random = Randomstorm()
		self.Jarvis = Jarvis()
		self.RedditNews = RedditNews()

	def start(self):
		try:
			self.Jarvis.ser.open()

		except Exception as e:
			print "[!] Arduino Leonardo not found, features that use keyboard will not work."

		try:
			self.Jarvis.Say(self.random.random('greetings'))
			while 1:
				try:
					self.command = self.Jarvis.Listen()
       		        		self.message = self.command.split()
        			        self.input_list = [str(a) for a in self.message]

					if self.input_list[0] == "exit":
						self.Jarvis.Say(self.random.random('salutes'))
						break

					elif self.input_list[0] == "sleep":
						while 1:
							self.wait = self.Jarvis.Listen()
							if self.wait == "Jarvis":
								self.Jarvis.Say(self.random.random('affirmative'))
								break

					elif self.input_list[0] == "newspaper":
						self.Jarvis.Say("Here are the news sir.")
						self.titles = self.RedditNews.get_headlines()
						self.RedditNews.speak_headlines(titles)

					elif self.input_list[0] == "start":
						self.Jarvis.SerialWrite(self.input_list[1])
						self.Jarvis.Say(self.random.random('affirmative'))

					elif self.input_list[0] == "say":
						self.Jarvis.Say(self.input_list[1:])

					elif self.input_list[0] == "run":
						self.Jarvis.Say(self.random.random('affirmative'))
						os.system("./scripts/{}.sh".format(self.input_list[1]))

					elif self.input_list[0] == "editor":
						self.Jarvis.Say("Starting edition mode sir.")
                                	        while 1:
                                     			self.editmode = self.Jarvis.Listen()
                                     	 		self.mesg = self.editmode
                                       	 	        #self.msg = "".join(self.mesg)

                                       	        	if self.mesg is not None:
								try:
									self.Jarvis.SerialWrite(self.mesg)
                                       	        			self.Jarvis.Say(self.random.random('affirmative'))
								except:
									print "[!] Feature not working, plug you Arduino Leonardo then try again."
									break
                                                	else:
								pass
							if self.editmode == "exit":
                                                        	self.Jarvis.Say("Stoping edition mode sir.")
								break

					else:
                       				print '[!] Input a valid option, enter "help" to see valid commands.'
						self.Jarvis.Say(self.random.random('dntunderstand'))

				except IndexError:
					pass
				except AttributeError:
					pass

		except KeyboardInterrupt:
			print "\n[*] User requested shutdown"
			self.Jarvis.Say(self.random.random('salutes'))
			exit()
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

