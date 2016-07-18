import sys
from subprocess import *
import time
import readline

class Completer:

        def __init__(self,console):
		tab = readline.parse_and_bind("tab: complete")
		if console == "pythem":
			completer = readline.set_completer(self.pythem)
		elif console == "xploit":
			completer = readline.set_completer(self.xploit)

	def suboption(self, text, state):
		#print text
		#print state
		results = [x for x in self.suboptions if x.startswith(text)] + [None]
		return results[state]


	def xploit(self, text, state):
		#print text
		#print state
		if "set" in text and state == 1:
			self.suboptions = ['addr1','addr2','arch','lenght','shellcode','nops','offset']
			completer = readline.set_completer(self.suboption)
		elif "print" in text and state == 1:
			self.suboptions = ['addr1','addr2','arch','lenght','shellcode','nops','offset']
			completer = readline.set_completer(self.suboption)
		elif "search" in text and state == 1:
			self.suboptions = ['opcode','instructions']
			completer = readline.set_completer(self.suboption)
		else:
			self.words = ['clear','help','exit','quit','search','fuzz','xploit','decode','encode','print','set']


        def pythem(self, text, state):
		#print text
		#print state
		if "set" in text and state == 1:
			self.suboptions = ['interface','arpmode','target','gateway','file']
			completer = readline.set_completer(self.suboption)

		elif "jarvis" in text and state == 1:
			self.suboptions = ['help','log','say','read']
			completer = readline.set_completer(self.suboption)

		elif "print" in text and state == 1:
			self.suboptions = ['interface', 'arpmode', 'target', 'gateway','file']
			completer = readline.set_completer(self.suboption)

		elif "scan" in text and state == 1:
			self.suboptions = ['tcp','arp','manual']
			completer = readline.set_completer(self.suboption)

		elif "arpspoof" in text and state == 1:
			self.suboptions = ['start', 'stop']
			completer = readline.set_completer(self.suboption)

		elif "dnsspoof" in text and state == 1:
			self.suboptions = ['start','stop']
			completer = readline.set_completer(self.suboption)

		elif "xploit" in text and state == 1:
			self.suboptions = ['stdin', 'tcp']
			completer = readline.set_completer(self.suboption)

		elif "brute-force" in text and state == 1:
			self.suboptions = ['ssh','url','form']
			completer = readline.set_completer(self.suboption)
		else:
	        	self.words = ['clear','help','exit','quit','set','print','scan','arpspoof','dnsspoof','sniff','pforensic','xploit','brute','geoip','decode','encode','cookiedecode','jarvis']
			results = [x for x in self.words if x.startswith(text)] + [None]
			return results[state]



