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


import serial
import pyttsx
import speech_recognition as sr
import serial.tools.list_ports
import praw
import sqlite3
import random
import os,sys
import subprocess

class Jarvis(object):

	def __init__(self):
		self.status = 1
		self.version = "0.0.7"
		self.array = []
		self.numbers = []
		self.path = os.path.abspath(os.path.dirname(sys.argv[0]))
		try:
			self.con = sqlite3.connect(self.path + "config/Jarbas.db")
		except:
			g = self.path.split("core")
			dbpath = g[0] + "/config/Jarbas.db"
			self.con = sqlite3.connect(dbpath)
		self.serialport = self.arduino_check()
		self.rec = sr.Recognizer()
		self.engine = pyttsx.init()
		self.rate = self.engine.getProperty('rate')
		self.engine.setProperty('rate', self.rate-60)
		self.voices = self.engine.getProperty('voices')
		self.engine.setProperty('voice',self.voices[16].id) #1,9,10,11,16,22,25
		self.ser = serial.Serial()
		self.ser.port = self.serialport
		self.ser.baudrate = 9600

	def onEnd(self, name, completed):
		self.engine.endLoop()

	def Jarvis(self, text):
		self.string = str(text)
		self.engine = pyttsx.init()
		self.engine.connect('finished-utterance', self.onEnd)
		self.engine.say(self.string)
		self.engine.startLoop()

	def SayIgnore(self, text):
		self.result = text.encode('ascii','ignore')
		self.Say(self.result)
		self.Say(" ")

	def Say(self, text):
		self.Jarvis(text)
		self.Jarvis(" ")

	def Listen(self):
		with sr.Microphone() as source:
			self.audio = self.rec.listen(source)
		try:
			self.result = self.rec.recognize_google(self.audio)
			print self.result
			return self.result
		except sr.UnknownValueError:
        	        print("Google Speech Recognition could not understand audio")
        	except sr.RequestError:
                	self.Say("Could not request results from Google Speech Recognition service master, check our internet connection.")
	def Read(self, file):
		words = open(file, "r")
		text = words.read()
		self.Say(text)

	def get_ports(self):
		self.ports = serial.tools.list_ports.comports()
		for p in self.ports:
			return p

	def arduino_check(self):
		self.result = self.get_ports()

		if self.result is not None:
			for i in self.result:
				self.array.append(i)
			if "Arduino Leonardo" in self.array:
				index = self.array.index("Arduino Leonardo")
				nport = index -1
				port = self.array[nport]
				return port
			else:
				print "[!] Arduino Leonardo not found."
				pass
		else:
			pass



	def SerialWrite(self, list):
		self.command = str(list)
		self.ser.write(self.command)


	def start(self):
		try:
			#devnull = open(os.devnull, 'wb')
			#p = subprocess.Popen(["python", path], shell=False, stdout=subprocess.PIPE, stderr=devnull)
			out = self.path + "/log/jarvisout.txt"
			err = self.path + "/log/jarviserr.txt"
			path = self.path + "/core/processor.py"
			with open(out, "a+") as stdout, open(err, "a+") as stderr:
				self.p = subprocess.Popen(["python", path], shell=False, stdout=stdout, stderr=stderr)
		except Exception as e:
			print "[!] Exception caught: {}".format(e)

	def stop(self):
		self.p.terminate()

	def GetNews(self, limit=10):
		self.r = praw.Reddit(user_agent="Jarvis by /u/m4n3dw0lf")
		self.subs = self.r.get_subreddit("worldnews").get_hot(limit=limit)
		self.headlines = []
		for sub in self.subs:
			self.headlines.append(sub.title)
		return self.headlines

	def SpeakNews(self, news=[]):
		try:
			for a in news:
				self.SayIgnore(a)
				self.SayIgnore("Next")
			self.Say("I Finished reading the news sir.")
		except KeyboardInterrupt:
			print "[*] User requested interrupt"
			exit()
		except Exception as e:
			print "[!] Exception caught: {}".format(e)
			exit()

	def random(self, arg):
		with self.con:
			self.cur = self.con.cursor()
                        cont = self.cur.execute("SELECT max(id) FROM {}".format(arg))
                        cont = self.cur.fetchone()
                        for i in range(1,cont[0]+1):
                                self.numbers.append(i)
                        self.cur.execute("SELECT * FROM {} where id = {} limit 1".format(arg,random.choice(self.numbers)))
                        id,msg = self.cur.fetchone()
                        return msg

