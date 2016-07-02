# PytheM

PytheM is a python pentesting framework. Same has been developed in the hope that it will be useful and i don't take responsabillity of any misapplication of it. Only for GNU/Linux OS, check wiki to see examples:<br/> https://github.com/m4n3dw0lf/PytheM/wiki<br/> 

#Installation

$sudo git clone https://github.com/m4n3dw0lf/PytheM/ <br />
(OPTIONAL)<br />
plug your Arduino Leonardo <br />
open the arduino IDE > Tools > Board then select Arduino Leonardo <br />
go to Tools> Serial port and check the serial port of the Arduino Leonardo <br />
press CTRL+O <br />
navigate to the directory: path/../PytheM/core/heart/jarvis/ <br />
select the jarvis.ino file then upload to the Arduino Leonardo. <br />
(CLOSE OPTIONAL) <br />

$cd PytheM<br/>

$sudo pip install -r requirements.txt <br />
(if NetfilterQueue error)<br />
$sudo apt-get update<br />
$sudo apt-get install build-essential python-dev libnetfilter-queue-dev<br />
$sudo pip install -r requirements.txt <br />
(Close NetfilterQueue error) <br />

(if PyAudio gcc error)<br />
$sudo apt-get update<br />
$sudo apt-get install libasound-dev libjack-jackd2-dev portaudio19-dev python-pyaudio<br />
$sudo pip install -r requiremenst.txt <br />
(Close PyAudio error) <br />

Now you are ready to rock:<br /> 
$sudo ./pythem <br/>

#Features
```
[ PytheM - Penetration Testing Framework v0.3.2 ]

[*] help:		Print this help message.


[*] exit/quit:		Leave the program.


[*] set			Set a variable value.

parameters:

 - interface
 - gateway
 - target
 - file
 - arpmode

  examples:

   pythem> set interface         | open input to set
	  or
   pythem> set interface wlan0   | don't open input to set value


[*] print		Print variable value.

  examples:

   pythem> print gateway


[*] scan		Make a tcp/manualport/arp scan.

(Should be called after setting interface and target)

  examples:

   pythem> scan
	  or
   pythem> scan tcp


[*] arpspoof		Start or stop a arpspoofing attack.

(Optional setting arpmode to select arpspoofing mode should be filled with rep or req) 
(rep to spoof responses, req to spoof requests)

arguments:

 start
 stop

  examples:
   arpspoof start
   arpspoof stop


[*] dnsspoof		Start a dnsspoofing attack.

(Should be called after a arpspoofing attack have been started)

  examples:

   pythem> dnsspoof start
   pythem> dnsspoof stop


[*] sniff		Start sniffing packets.

(Should be called after setting interface)

  examples:

   pythem> sniff http
	  or
   pythem> sniff
   [+] Enter the filter: port 1337 and host 10.0.1.5  | tcpdump like format or http,dns specific filter.


[*] pforensic		Start a packet-analyzer<br />

(Should be called after setting interface and file with a .pcap file)

  examples:

   pythem> pforensic
   pforensic> help


[*] brute-force		Start a brute-force attack.

(Should be called after setting target and wordlist file path)

arguments:

 ssh		| ip address as target
 url		| url (with http:// or https://) as target
 webform	| url (with http:// or https://)as target

  examples:

   pythem> brute-force webform
   pythem> brute-force ssh


[*] geoip		Geolocalizate approximately the location of a IP address.


(Should be called after setting target (Ip address))

  examples:

   pythem> geoip
	  or
   pythem> geoip 8.8.8.8


[*] decode and encode	Decode or encode a string with choosen pattern

  examples:

   pythem> decode base64
   pythem> encode ascii


[*] cookiedecode	Decode a base64 url encoded cookie value.

  example:

   pythem> cookiedecode


* Anything else will be executed in the terminal like cd, ls, nano, cat, etc. *
```
### Jarvis - voice-controlled assistant
link: https://github.com/m4n3dw0lf/Jarvis
```
[*] jarvis

type jarvis-help to see the jarvis help page.

  examples:

   pythem> jarvis	  (Call Jarvis in speech recognition mode)

   pythem> jarvis-help    (Print Jarvis help message)

   pythem> jarvis-log     (Check Jarvis log)
	  or
   pythem> jarvis-log err

   pythem> jarvis-say     (Ask Jarvis to say something)
	  or
   pythem> jarvis-say hello my name is jarvis.

   pythem> jarvis-read 	  (If no file specified, should be called after setting file)
   	  or
   pythem> jarvis-read file.txt

```
by: m4n3dw0lf<br/>
