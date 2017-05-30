![alt text](https://img.shields.io/badge/version-v0.7.0-yellow.svg)
![alt text](https://img.shields.io/badge/python-2.7-blue.svg)
![alt text](https://img.shields.io/badge/OS-GNU%2FLinux-000000.svg)
[![alt text](https://img.shields.io/badge/donate-bitcoin-orange.svg)](https://blockchain.info/address/1Eggia3JXwWiR4mkVqztionNUfs2N3ghAd)


# PytheM - Penetration Testing Framework

PytheM is a python multi-purpose pentest framework. It has been developed to be used by security researchers and security professionals. The tool intended to be used only for acts within the law. I am not liable for any undue and unlawful act practiced by this tool, for more information, read the license. Only runs on GNU/Linux OS.

![alt text](config/pythembkg.png)

## Installation

- [Installation guide](https://github.com/m4n3dw0lf/PytheM/wiki/Installation#installation)

#### Quick-Start
```
$sudo apt-get update
$sudo apt-get install build-essential python-dev tcpdump python-capstone
$sudo apt-get install libnetfilter-queue-dev libffi-dev libssl-dev
$sudo git clone https://github.com/m4n3dw0lf/PytheM
$cd PytheM
$sudo pip install -r requirements.txt 

Run with:
$sudo ./pythem.py
```

## Examples

- [ARP spoofing - Man-in-the-middle](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#arp-spoofing---man-in-the-middle).
- [Man-in-the-middle HSTS bypass - Strip SSL](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#man-in-the-middle-hsts-bypass---strip-ssl)
- [ARP+DNS spoof - fake page redirect to credential harvester](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#arpdns-spoof---fake-page-redirect-to-credential-harvester)
- [DHCP ACK Injection spoofing - Man-in-the-middle](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#man-in-the-middle-dhcp-spoofing---dhcp-ack-injection)
- [Man-in-the-middle inject BeEF hook](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#inject-beef-hook)
- [SSH Brute-Force attack](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#ssh-brute-force-attack).
- [Web page formulary brute-force](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#web-page-formulary-brute-force)
- [URL content buster](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#url-content-buster)
- [Overthrow the DNS of LAN range/IP address](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#overthrow-the-dns-of-lan-rangeip-address)
- [Redirect all possible DNS queries to host](https://github.com/m4n3dw0lf/PytheM/wiki/Examples#redirect-all-possible-dns-queries-to-host)

## Exploit Development with PytheM

- [Exploit Development 1: Overwriting Instruction Pointer](https://github.com/m4n3dw0lf/PytheM/wiki/Exploit-development#exploit-development-1-overwriting-instruction-pointer)
- [Exploit Development 2: Ret2libc](https://github.com/m4n3dw0lf/PytheM/wiki/Exploit-development#exploit-development-2-ret2libc)

## Commands Reference

### Index

#### Core
  - [help](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#help)
  - [exit/quit](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#exitquit)
  - [set](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#set)
  - [print](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#print)

#### Network, Man-in-the-middle and Denial of service (DOS)<br>
  - [arpspoof](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#arpspoof)
  - [dhcpspoof](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#dhcpspoof)
  - [dnsspoof](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#dnsspoof)
  - [hstsbypass](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#hstsbypass)
  - [redirect](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#redirect)
  - [sniff](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#sniff)
  - [dos](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#dos)
  - [pforensic](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#pforensic)
    <br>**pforensic: Commands Reference**<br>
    - [help](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#help-1)
    - [clear](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#clear)
    - [exit/quit](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#exitquit-1)
    - [show](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#show)
    - [conversations](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#conversations)
    - [packetdisplay](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#packetdisplay-num)
    - [filter](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#filter-stringlayer)

#### Exploit development and Reverse Engineering<br>
  - [xploit](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#xploit)
    <br>**xploit: Commands Reference**<br>
    - [help](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#help-2)
    - [clear](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#clear-1)
    - [exit/quit](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#exitquit-2)
    - [set](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#set-1)
    - [decode/encode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#decodeencode)
    - [shellcode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#shellcode)
    - [search](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#search)
    - [xploit](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#xploit-1)
    - [cheatsheet](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#cheatsheet)
    - [fuzz](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#fuzz)
#### Brute Force<br>
  - [brute](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#brute)

#### Utils<br>
  - [geoip](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#geoip)
  - [decode/encode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#decodeencode-1)
  - [cookiedecode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#cookiedecode)
