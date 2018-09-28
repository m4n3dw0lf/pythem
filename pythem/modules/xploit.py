#!/usr/bin/env python2.7

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


import os
import fcntl
import signal
import sys
import struct
import resource
import time
import termcolor
import threading
from utils import *
from netaddr import IPAddress, AddrFormatError
import subprocess
from subprocess import *
from socket import *
from ropper import RopperService
import termcolor
from time import sleep
from completer import Completer


class Exploit(object):
    name = "Exploit development interactive shell."
    desc = "use gdb plus ROPgadget + offset generator and memaddresses to create exploits."

    def __init__(self, target, mode):
        self.version = '0.0.5'
        self.target = target
        self.mode = mode
        self.xtype = 'bufferoverflow'
        self.offset = 1
        self.nops = 0
        self.shellcode = ''
        self.lenght = 0
        self.addr1 = None
        self.addr2 = None
        self.arch = 'x86'
        self.port = 0
        if self.target:
            self.p1 = Popen(['gdb', "--silent", "{}".format(self.target)], stdin=PIPE, stdout=PIPE, bufsize=1)
            gdbout = self.p1.stdout.readline()
        else:
            self.p1 = Popen(['gdb', '--silent'], stdin=PIPE, stdout=PIPE, bufsize=1)
            # gdbout = self.p1.stdout.readline()
        completer = Completer(".gdb_history", "xploit")

    def gdb(self, cmd):
        def signal_handler(signum, frame):
            print 1 + "that's ugly"

        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(1)
        try:
            print >> self.p1.stdin, cmd
            for line in iter(self.p1.stdout.readline, b''):
                print line
        except KeyboardInterrupt:
            pass
        except Exception as e:
            # print "[!] Exception caught: {}".format(e)
            pass

    def getshellcode(self, file):
        os.system("for i in $(objdump -d {} |grep '^ ' |cut -f2); do echo -n '\\x'$i; done; echo".format(file))

    def search(self, file, search, find):
        options = {'color': True,
                   'detailed': True}
        rs = RopperService(options)
        ls = file
        rs.addFile(ls)
        rs.setArchitectureFor(name=ls, arch=self.arch)
        if search == "instructions":
            os.system('ropper --file {} --search "{}"'.format(self.target, find))
        elif search == "opcode":
            os.system('ropper --file {} --opcode "{}"'.format(self.target, find))
        else:
            print "[!] Select a valid search (instructions/opcode)."
            return

    def pattern(self, size=1024):
        return "\x41" * size

    def nops(self, size=1024):
        return "\x90" * size

    def int2hexstr(self, num, intsize=4):
        if intsize == 8:
            if num < 0:
                result = strct.pack("<q", num)
            else:
                result = struct.pack("<Q", num)
        else:
            if num < 0:
                result = struct.pack("<l", num)
            else:
                result = struct.pack("<L", num)

        return result

    def list2hexstr(self, intlist, intsize=4):
        result = ""
        for value in intlist:
            if isinstance(value, str):
                result += value
            else:
                result += self.int2hexstr(value, intsize)

        return result

    def run(self):
        padding = self.pattern(self.offset)
        payload = [padding]

        if self.xtype == "bufferoverflow":
            if self.arch == "x86":
                if self.addr1 is not None:
                    payload += [self.addr1]
                if self.addr2 is not None:
                    payload += [self.addr2]
                if self.nops > 0:
                    payload += ["{}".format(self.nops(self.nops))]

                payload += [self.shellcode]
                total = len(payload) - self.lenght
                fill = self.pattern(total)
                payload += [fill]
                payload = self.list2hexstr(payload)
                print "[+] Writing payload into buffer.txt"
                f = open("buffer.txt", "w")
                f.write(payload)

            elif self.arch == "x64":
                if self.addr1 is not None:
                    payload += struct.pack("<Q", int(self.addr1))
                if self.addr2 is not None:
                    payload += struct.pack("<Q", int(self.addr2))
                if self.nops > 0:
                    payload += ["{}".format(self.nops(self.nops))]

                payload += [self.shellcode]
                total = len(payload) - self.lenght
                fill = self.pattern(total)
                payload += [fill]
                payload = self.list2hexstr(payload, 8)
                print "\n[+] Writing payload into buffer.txt\n"
                f = open("buffer.txt", "w")
                f.write(payload)
            else:
                print "[!] Select a valid processor architecture."
                return

        if self.mode == "tcp":
            self.port = input("[+] Enter the tcp port to fuzz: ")
            self.tcppwn(payload)

        elif self.mode == "stdin":
            self.stdinpwn(payload)
        else:
            print "[!] Select a valid mode (stdin or tcp)."

    def stdinpwn(self, payload):
        resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
        P = Popen(self.target, stdin=PIPE)
        print "[*] Sending buffer with lenght: " + str(len(payload))
        P.stdin.write(payload)
        while True:
            line = sys.stdin.readline()
            P.poll()
            ret = P.returncode
            if ret is None:
                P.stdin.write(line)
            else:
                if ret == -11:
                    print "[*] Child program crashed with SIGSEGV"
                else:
                    print "[-] Child program exited with code %d" % ret
                break

        print "\n If it does not work automatically, run on terminal: (cat buffer.txt ; cat) | {}".format(self.target)

    def tcppwn(self, payload):
        try:
            self.target = str(IPAddress(self.target))
        except AddrFormatError as e:
            try:
                self.target = gethostbyname(self.target)
            except Exception as e:
                print "[-] Select a valid IP address or domain name as target."
                print "[!] Exception caught: {}".format(e)
                return

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(4)
            self.socket.connect((self.target, self.port))
            self.socket.send(payload)
            while True:
                self.socket.recv(1024)
        except KeyboardInterrupt:
            return

        except Exception as e:
            if 'Connection refused' in e:
                print "[-] Connection refused."
                return

    def start(self):
        while True:
            try:
                console = termcolor.colored("xploit>", "blue", attrs=["bold"])
                self.command = raw_input("{} ".format(console))
                os.system("echo {} >> .gdb_history".format(self.command))
                self.argv = self.command.split()
                self.input_list = [str(a) for a in self.argv]

                try:
                    if self.input_list[0] == 'exit' or self.input_list[0] == 'quit':
                        break

                    elif self.input_list[0] == 'help':
                        self.printHelp()

                    elif self.input_list[0] == 'clear':
                        os.system("clear")
                    elif self.input_list[0] == 'cat' or self.input_list[0] == '(cat':
                        os.system("cat {}".format(str(self.input_list[1])))
                    elif self.input_list[0] == 'python':
                        os.system("python {}".format(" ".join(self.input_list[1:])))
                    elif self.input_list[0] == 'echo':
                        os.system("echo {}".format(" ".join(self.input_list[1:])))
                    elif self.input_list[0] == 'ping':
                        os.system("ping {}".format(" ".join(self.input_list[1:])))
                    elif self.input_list[0] == 'nc':
                        os.system("nc {}".format(" ".join(self.input_list[1:])))

                    elif self.input_list[0] == 'search':
                        try:
                            file = self.target.replace("./", "")
                            try:
                                search = self.input_list[1]
                            except IndexError:
                                try:
                                    search = raw_input("[+] Search (instructions/opcode): ")
                                except KeyboardInterrupt:
                                    pass

                            try:
                                find = raw_input("[+] Find: ")
                            except KeyboardInterrupt:
                                pass
                            self.search(file, search, find)

                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == 'fuzz':
                        try:
                            from fuzzer import SimpleFuzz
                            self.fuzz = SimpleFuzz(self.target, self.mode, self.offset)
                        except KeyboardInterrupt:
                            pass
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)
                            pass
                    elif self.input_list[0] == 'shellcode':
                        self.getshellcode(self.input_list[1])

                    elif self.input_list[0] == 'cheatsheet':
                        self.gdbCheatSheet()

                    elif self.input_list[0] == 'xploit':
                        self.run()

                    elif self.input_list[0] == "decode":
                        try:
                            print decode(self.input_list[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            type = raw_input("[+] Type of decoding: ")
                            print decode(type)

                    elif self.input_list[0] == "encode":
                        try:
                            print encode(self.input_list[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            type = raw_input("[+] Type of encoding: ")
                            print decode(type)

                    elif self.input_list[0] == "encoder":
                        try:
                            if self.input_list[1]:
                                string = " ".join(self.input_list[1:])
                        except:
                            string = raw_input("[+] String to encode: ")

                        try:
                            opt = raw_input("[?] Output, [A]Address/[S]Shellcode/[L]LittleEndian (A/S/L): ")
                            rev_string_hex = string[::-1].encode('hex')

                            if opt.lower() == "a":
                                if len(string) > 8:
                                    print "[-] String overflow the 64bit address space."
                                else:
                                    print "0x" + rev_string_hex

                            elif opt.lower() == "s":
                                array = []
                                for i in rev_string_hex:
                                    array.append(i)
                                result = zip(*[array[x::2] for x in (0, 1)])
                                buf = ""
                                for x, y in result:
                                    buf += "\\x{}{}".format(x, y)
                                print buf

                            elif opt.lower() == "l":
                                print rev_string_hex

                            else:
                                print "[!] Invalid option"
                        except KeyboardInterrupt:
                            pass

                    elif self.input_list[0] == "decoder":
                        try:
                            if self.input_list[1]:
                                string = " ".join(self.input_list[1:])
                        except:
                            string = raw_input("[+] Shellcode/Address/LittleEndian String to decode: ")

                        try:
                            string = string.strip("\\x")
                        except:
                            pass

                        try:
                            string = string.strip("0x")
                        except:
                            pass

                        try:
                            array = []
                            for i in string:
                                array.append(i)
                            result = zip(*[array[x::2] for x in (0, 1)])
                            result = result[::-1]
                            buf = ""
                            for x, y in result:
                                buf += "{}{}".format(x, y)
                            print buf.decode("hex")
                        except Exception as e:
                            print "[!] Exception caught: {}".format(e)

                    elif self.input_list[0] == "print":
                        if self.input_list[1] == "offset":
                            print "[+] Offset "
                            print "[+] lenght: {}".format(self.offset)
                        elif self.input_list[1] == "nops":
                            print "[+] Nops "
                            print "[+] lenght: {}".format(self.nops)
                        elif self.input_list[1] == "shellcode":
                            print "[+] Shellcode "
                            print "[+] lenght: {}".format(self.shellcode)
                        elif self.input_list[1] == "lenght":
                            print "[+] Total payload lenght "
                            print "[+] lenght: {}".format(self.lenght)
                        elif self.input_list[1] == "addr1":
                            print "[+] First address to overwrite"
                            print "[+] memory address 1: {}".format(self.addr1)
                        elif self.input_list[1] == "addr2":
                            print "[+] Second address to overwrite"
                            print "[+] memory address 2: {}".format(self.addr2)
                        elif self.input_list[1] == "arch":
                            print "[+] Target system arch"
                            print "[+] Architecture: {}".format(self.arch)
                        else:
                            cmd = ' '.join(self.input_list[0:])
                            data = self.gdb(cmd)
                            if data:
                                print color("{}".format(data), "blue")


                    elif self.input_list[0] == "set" or self.input_list[0] == "SET":

                        if self.input_list[1] == "offset":
                            try:
                                self.offset = int(self.input_list[2])
                            except IndexError:
                                try:
                                    self.offset = input("[+] Enter the offset (number of 'A's): ")
                                except KeyboardInterrupt:
                                    pass

                        elif self.input_list[1] == "nops":
                            try:
                                self.nops = int(self.input_list[2])
                            except IndexError:
                                try:
                                    self.nops = input("[+] Enter the NOPsled (number of NOPs): ")

                                except KeyboardInterrupt:
                                    pass

                        elif self.input_list[1] == "shellcode":
                            try:
                                self.shellcode = input("[+] Enter the shellcode: ")
                            except KeyboardInterrupt:
                                pass

                        elif self.input_list[1] == "lenght":
                            try:
                                self.lenght = int(self.input_list[2])
                            except IndexError:
                                try:
                                    self.lenght = input("[+] Enter the payload total lenght: ")
                                except KeyboardInterrupt:
                                    pass

                        elif self.input_list[1] == "addr1":
                            try:
                                self.addr1 = input("[+] First address to overwrite: ")
                            except KeyboardInterrupt:
                                pass

                        elif self.input_list[1] == "addr2":
                            try:
                                self.addr2 = input("[+] Second address to overwrite: ")
                            except KeyboardInterrupt:
                                pass

                        elif self.input_list[1] == "arch":
                            try:
                                self.arch = self.input_list[2]
                            except IndexError:
                                try:
                                    self.arch = raw_input("[+] Target system arch: ")
                                except KeyboardInterrupt:
                                    pass

                        else:
                            cmd = ' '.join(self.input_list[0:])
                            data = self.gdb(cmd)
                            if data:
                                print color("{}".format(data), "blue")

                    else:
                        try:
                            cmd = ' '.join(self.input_list[0:])
                            data = self.gdb(cmd)
                            if data:
                                print color("{}".format(data), "blue")
                        except Exception as e:
                            # DEBUG
                            # print "[!] Select a valid option, type help to check sintax."
                            # print e
                            continue

                except IndexError:
                    pass
                except Exception as e:
                    print "[!] Exception caught: {}".format(e)



            except KeyboardInterrupt:
                break

    def printHelp(self):
        print
        print color("             [XPLOIT v{}]".format(self.version), "grey")
        print
        print
        print color("           TARGET - [ {} ]".format(self.target), "red")
        print
        print
        print color("[*] help:          Print this help message.", "blue")
        print
        print
        print color("[*] clear:         Clean the screen, same as GNU/Linux OS 'clear'.", "blue")
        print
        print
        print color("[*] exit/quit:             Return to pythem.", "blue")
        print
        print
        print color("[*] set                    Set the variables values.", "blue")
        print
        print color(" parameters:", "red")
        print
        print color("  - offset                 | Number os 'A's to overwrite the instruction pointer.", "yellow")
        print
        print color(
            "  - addr1                  | (Optional) Hexa(0xaddress) First address to overwrite after the offset.",
            "yellow")
        print
        print color(
            "  - addr2                  | (Optional) Hexa(0xaddress) Second address to overwrite after the offset.",
            "yellow")
        print
        print color(
            "  - nops                   | (Optional) Number of NOPs after IP overwrite or after the addr1 and addr2 if they are set.",
            "yellow")
        print
        print color(
            "  - shellcode                      | (Optional) Shellcode (could be generated by msfvenom or any other).",
            "yellow")
        print
        print color("  - lenght                 | Total lenght of the payload.", "yellow")
        print
        print color("  - arch                   | Target system processor architecture.", "yellow")
        print
        print
        print color("[*] print          Print a variable's value.", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "print offset"
        print
        print
        print color("[*] decode/encode          Decode or encode a string with a chosen pattern.", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "decode hex"
        print color("  xploit> ", "blue") + "encode hex"
        print
        print
        print color("[*] encoder        Encode string as address / shellcode / little endian", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "encoder abcd"
        print "  [?] Output, [A]Address/[S]Shellcode/[L]LittleEndian (A/S/L): s"
        print "\x64\x63\x62\x61"
        print
        print
        print color("[*] decoder        Decode address / shellcode / little endian into ASCII", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "decoder 0x636261"
        print "  abc"
        print
        print
        print color("[*] shellcode      Get the shellcode of executable file", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "shellcode compiled_program"
        print
        print
        print color("[*] search         Automatically search for instructions or opcode in the binary executable.",
                    "blue")
        print
        print color(" parameters:", "red")
        print
        print color("  - instructions", "yellow")
        print
        print color("  - opcode", "yellow")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "search"
        print "  [+] Search (instructions/opcode):"
        print "     or"
        print color("  xploit> ", "blue") + "search instructions" + color("                ? - any character", "green")
        print "  [+] Find: pop ?di" + color("                     % - any character", "green")
        print
        print color("  xploit>", "blue") + "search opcode"
        print "  [+] Find: ffe4"
        print
        print
        print color("[*] xploit         Run the exploit after all the settings.", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "xploit"
        print
        print
        print color("[*] cheatsheet             Display a GDB cheatsheet ;).", "blue")
        print
        print color(" examples:", "red")
        print
        print color("  xploit> ", "blue") + "cheatsheet"
        print
        print
        print color("[*] fuzz           Start fuzzing on subject.", "blue")
        print
        print "If file is passed to xploit will fuzz stdin"
        print "If target is passed to xploit will fuzz tcp"
        print
        print "The offset's value will be the number of 'A's to send."
        print
        print "[Default = 1]"
        print "will be increased in 1 by 1."
        print "example:"
        print "[offset = 10]"
        print "will be increased in 10 by 10."
        print
        print color(" examples:", "green")
        print
        print color("  xploit> ", "blue") + "fuzz"
        print
        print
        print color("* Anything else will be executed in GNU debugger shell with {} as file *".format(self.target),
                    "red")
        print

    def gdbCheatSheet(self):
        print " ____________________________________________________________________________________ "
        print "|<where>:                                |<what>:                                     |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|function_name                           |expression                                  |"
        print "|*function_name+<point> (disas function  |address                                     |"
        print "|line_number             to get <point>) |$register                                   |"
        print "|file:line_number                        |filename::variable_name                     |"
        print "|                                        |function::variable_name                     |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Registers:                              |Formats:                                    |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|General Purpose Registers:              |                                            |"
        print "|ax - Accumulator register               |a     Pointer                               |"
        print "|bx - Base register                      |c     Read as integer,print as char         |"
        print "|cx - Counter register                   |d     Integer                               |"
        print "|dx - Data register (I/O)                |f     Float                                 |"
        print "|                                        |o     Integer as octal                      |"
        print "|Index Registers:                        |s     String                                |"
        print "|si - Source index (string)              |t     Integer as binary                     |"
        print "|di - Destination index (string) |u     Integer, unsigned decimal             |"
        print "|ip - Instruction pointer                |x     Integer, as hexadecimal               |"
        print "|                                        |                                            |"
        print "|Stack Registers:                        |                                            |"
        print "|bp - Base pointer                       |                                            |"
        print "|sp - Stack pointer                      |                                            |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Conditions:                             |Signals:                                    |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|break/watch <where> if <condition>      |handle <signal> <options>                   |"
        print "|condition <breakpoint#> <condition>     |<options>:                                  |"
        print "|                                        |(no)print                                   |"
        print "|                                        |(no)stop                                    |"
        print "|                                        |(no)pass                                    |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Manipulating the program:               |Running:                                    |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|set var <variable_name>=<value> |run / r                                     |"
        print "|return <expression>                     |kill / k                                    |"
        print "|jump <where>                            |                                            |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Variables and memory:                   |Informations:                               |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|print/format <what>                     |disassemble / disas                         |"
        print "|display/format <what>                   |disassemble / disas <where>                 |"
        print "|undisplay <display#>                    |info args                                   |"
        print "|enable display <display#>               |info breakpoints                            |"
        print "|disable display <display#>              |info display                                |"
        print "|x/nf <address/variable/register>        |info locals                                 |"
        print "|n:how many units to print               |info sharedlibrary                          |"
        print "|f: format character                     |info threads                                |"
        print "|                                        |info directories                            |"
        print "|                                        |info registers                              |"
        print "|                                        |whatis variable_name                        |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Watchpoints:                            |Stepping:                                   |"
        print "|---------------------------------------|--------------------------------------------|"
        print "|watch <where>                           |step / s                                    |"
        print "|delete/enable/disable <watchpoint#>     |next / n                                    |"
        print "|                                        |finish / f                                  |"
        print "|                                        |continue / c                                |"
        print "|_______________________________________|____________________________________________|"
        print " ____________________________________________________________________________________ "
        print "|Breakpoints:                            | Examining the stack:                       |"
        print "|---------------------------------------|--------------------------------------------|"
        print "| break / br <where>                    | backtrace / bt                             |"
        print "| delete <breakpoint#>                  | where                                      |"
        print "| clear                                 | backtrace full                             |"
        print "| enable <breakpoint#>                  | where full                                 |"
        print "| disable <breakpoint#>                 | frame <frame#>                      |"
        print "|_______________________________________|____________________________________________|"


if __name__ == "__main__":
    try:
        if sys.argv[1]:
            xploit = Exploit(sys.argv[1], "stdin")
        xploit.start()
    except:
        xploit = Exploit(None, "stdin")
        xploit.start()
