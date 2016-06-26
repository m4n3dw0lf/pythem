# PytheM

PytheM is a python network/pentesting tool. Same has been developed in the hope that it will be useful and i don't take responsabillity of any misapplication of it. Only for GNU/Linux OS 

#Installation

$sudo git clone https://github.com/m4n3dw0lf/PytheM/ <br />
$sudo pip install -r requirements.txt <br />
$sudo ./pythem <br/>

#Features

- help:			Print this help message.<br />


- exit/quit:		Leave the program.<br />


- set			Set a parameter value.<br />

 parameters:<br />

 - interface
 - gateway
 - target
 - file
 - arpmode

  examples: <br />

   pythem> set interface         |open input to set<br />


- scan			Make a tcp/manualport/arp scan.<br />

(Should be called after setting interface and target)<br />

  examples:<br />

   pythem> scan<br />


- arpspoof		Start or stop a arpspoofing attack.<br />

(Optional setting arpmode to select arpspoofing mode should be filled with rep or req)<br />
(rep to spoof responses, req to spoof requests) <br />

arguments:<br />

 - start
 - stop

  examples:<br />
   arpspoof start <br />
   arpspoof stop <br />


- dnsspoof		Start a dnsspoofing attack.<br />

(Should be called after a arpspoofing attack have been started)<br />

  examples:<br />

   pythem> dnsspoof start<br />
   pythem> dnsspoof stop<br />


- sniff			Start sniffing packets.<br />

(Should be called after setting interface)<br />

  examples:<br />

   pythem> sniff<br />
   [+] Enter the filter: port 1337 and host 10.0.1.5  | tcpdump like format<br />

- pforensic		Start a packet-analyzer<br />

(Should be called after setting interface and file with a .pcap file)

  examples:<br />

   pythem> pforensic<br />
   pforensic> help<br />

- brute-force		Start a brute-force attack.<br />

(Should be called after setting target and wordlist file path)<br />

arguments:<br />

 - ssh		| ip address as target<br />
 - url		| url (with http:// or https://) as target<br />
 - webform	| url (with http:// or https://)as target<br />

  examples:<br />

   pythem> brute-force webform<br />
   pythem> brute-force ssh<br />


- geoip			Geolocalizate approximately the location of a IP address.<br />


(Should be called after setting target (Ip address))<br />

  examples:<br />

   pythem> geoip<br />


- decode and encode	Decode or encode a string with choosen pattern<br />

  examples:<br />

   pythem> decode base64<br />
   pythem> encode ascii<br />


- cookiedecode		Decode a base64 url encoded cookie value.<br />

  example:<br />

   pythem> cookiedecode<br />


* Anything else will be executed in the terminal like cd, ls, nano, cat, etc. *<br />

(+) Call the voice-controlled assistant Jarvis<br />

link: https://github.com/m4n3dw0lf/Jarvis<br />

[*] jarvis <br />

type jarvis-help to see the jarvis help page.<br />

  examples:<br />

   pythem> jarvis
   pythem> jarvis-help<br />


by: m4n3dw0lf<br />


