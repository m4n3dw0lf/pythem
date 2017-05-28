# PytheM - Penetration Testing Framework v0.6.8

PytheM is a python multi-purpose pentest framework. It has been developed in the hope that it will be useful and I don't take responsibility for any misapplication of it. Only runs on GNU/Linux OS.

![alt text](config/pythembkg.png)

## Installation

- [Installation guide](https://github.com/m4n3dw0lf/PytheM/wiki/Installation#installation)

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
  - [inject](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#inject)
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
    - [fuzz](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#fuzz)

#### Brute Force<br>
  - [brute](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#brute)

#### Utils<br>
  - [geoip](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#geoip)
  - [decode/encode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#decodeencode-1)
  - [cookiedecode](https://github.com/m4n3dw0lf/PytheM/wiki/Commands-Reference#cookiedecode)
