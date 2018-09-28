# pythem - Penetration Testing Framework

![](https://img.shields.io/pypi/v/pythem.svg)
![](https://img.shields.io/badge/python-2.7-blue.svg)
![](https://img.shields.io/badge/OS-GNU%2FLinux-000000.svg)
![](https://img.shields.io/docker/automated/m4n3dw0lf/pythem.svg)
![](https://img.shields.io/docker/build/m4n3dw0lf/pythem.svg)
[![](https://img.shields.io/badge/donate-bitcoin-yellow.svg)](https://blockchain.info/address/1Eggia3JXwWiR4mkVqztionNUfs2N3ghAd)

pythem is a multi-purpose pentest framework written in Python. It has been developed to be used by security researchers and security professionals. The tool intended to be used only for acts within the law. I am not liable for any undue and unlawful act practiced by this tool, for more information, read the license.


![](img/pythembg.png)

[![](https://img.shields.io/badge/wiki--green.svg)](https://github.com/m4n3dw0lf/pythem/wiki)

## Installation

> Links:

- [Create a Desktop Shortcut](https://github.com/m4n3dw0lf/pythem/wiki/Installation#create-a-desktop-shortcut)

![](img/desktopicon-wiki.png)
<br><br>
### Linux Installation

#### Dependencies Installation

> **NOTE:** Tested only with Debian-based distros, feel free to try the dependencies installation with **yum** or **zypper** if you use Redhat-like or SUSE-like.

```
sudo apt-get update
sudo apt-get install -y build-essential python-dev python-pip tcpdump python-capstone \
libnetfilter-queue-dev libffi-dev libssl-dev
```

#### Installation

- With **pip**:

```
sudo pip install pythem
```

- With **source**:

```
git clone https://github.com/m4n3dw0lf/pythem
cd pythem
sudo python setup.py install
```

- With **source** and **pip**:
```
git clone https://github.com/m4n3dw0lf/pythem
cd pythem
sudo python setup.py sdist
sudo pip install dist/*
```

#### Running

- Call on a terminal (Requires **root** privileges):

```
$ sudo pythem
```

<br><br>

### Running as Docker container

- Requires Docker

```
docker run -it --net=host --rm --name pythem m4n3dw0lf/pythem
```

<br><br>

## Usage

![](img/pythem.gif)

### Examples

- [ARP spoofing - Man-in-the-middle](https://github.com/m4n3dw0lf/pythem/wiki/Examples#arp-spoofing---man-in-the-middle).
- [ARP+DNS spoof - fake page redirect to credential harvester](https://github.com/m4n3dw0lf/pythem/wiki/Examples#arpdns-spoof---fake-page-redirect-to-credential-harvester)
- [DHCP ACK Injection spoofing - Man-in-the-middle](https://github.com/m4n3dw0lf/pythem/wiki/Examples#man-in-the-middle-dhcp-spoofing---dhcp-ack-injection)
- [Man-in-the-middle inject BeEF hook](https://github.com/m4n3dw0lf/pythem/wiki/Examples#inject-beef-hook)
- [SSH Brute-Force attack](https://github.com/m4n3dw0lf/pythem/wiki/Examples#ssh-brute-force-attack).
- [Web page formulary brute-force](https://github.com/m4n3dw0lf/pythem/wiki/Examples#web-page-formulary-brute-force)
- [URL content buster](https://github.com/m4n3dw0lf/pythem/wiki/Examples#url-content-buster)
- [Overthrow the DNS of LAN range/IP address](https://github.com/m4n3dw0lf/pythem/wiki/Examples#overthrow-the-dns-of-lan-rangeip-address)
- [Redirect all possible DNS queries to host](https://github.com/m4n3dw0lf/pythem/wiki/Examples#redirect-all-possible-dns-queries-to-host)
- [Get Shellcode from binary](https://github.com/m4n3dw0lf/pythem/wiki/Examples#get-shellcode-from-binary)
- [Filter strings on pcap files](https://github.com/m4n3dw0lf/pythem/wiki/Examples#filter-strings-on-pcap-files)
- [Exploit Development 1: Overwriting Instruction Pointer](https://github.com/m4n3dw0lf/pythem/wiki/Exploit-development#exploit-development-1-overwriting-instruction-pointer)
- [Exploit Development 2: Ret2libc](https://github.com/m4n3dw0lf/pythem/wiki/Exploit-development#exploit-development-2-ret2libc)

### Developing

- [Running tests](https://github.com/m4n3dw0lf/pythem/wiki/Developing#running-tests).

### Commands Reference

#### Index

##### Core
  - [help](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#help)
  - [exit/quit](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#exitquit)
  - [set](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#set)
  - [print](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#print)

##### Network, Man-in-the-middle and Denial of service (DOS)<br>
  - [scan](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#scan)
  - [webcrawl](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#webcrawl)
  - [arpspoof](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#arpspoof)
  - [dhcpspoof](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#dhcpspoof)
  - [dnsspoof](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#dnsspoof)
  - [redirect](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#redirect)
  - [sniff](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#sniff)
  - [dos](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#dos)
  - [pforensic](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#pforensic)
    <br>**pforensic: Commands Reference**<br>
    - [help](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#help-1)
    - [clear](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#clear)
    - [exit/quit](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#exitquit-1)
    - [show](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#show)
    - [conversations](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#conversations)
    - [packetdisplay](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#packetdisplay-num)
    - [filter](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#filter-stringlayer)

##### Exploit development and Reverse Engineering<br>
  - [xploit](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#xploit)
    <br>**xploit: Commands Reference**<br>
    - [help](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#help-2)
    - [clear](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#clear-1)
    - [exit/quit](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#exitquit-2)
    - [set](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#set-1)
    - [shellcode](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#shellcode)
    - [encoder](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#encoder)
    - [decoder](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#decoder)
    - [search](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#search)
    - [xploit](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#xploit-1)
    - [cheatsheet](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#cheatsheet)
    - [fuzz](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#fuzz)
    - [decode/encode](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#decodeencode)

##### Brute Force<br>
  - [brute](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#brute)

##### Utils<br>
  - [decode/encode](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#decodeencode-1)
  - [cookiedecode](https://github.com/m4n3dw0lf/pythem/wiki/Commands-Reference#cookiedecode)
