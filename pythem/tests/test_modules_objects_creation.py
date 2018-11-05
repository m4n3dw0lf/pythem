import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import unittest

class TestModulesObjectsCreation(unittest.TestCase):
    def test_redirect(self):
        from pythem.modules.redirect import Redirect
        redirect = Redirect()
    def test_arpspoof(self):
        from pythem.modules.arpoisoner import ARPspoof
        arpspoof = ARPspoof()
    def test_dhcpspoof(self):
        from pythem.modules.dhcpoisoner import DHCPspoof
        dhcpspoof = DHCPspoof()
    def test_dnsspoof(self):
        from pythem.modules.dnspoisoner import DNSspoof
        dnsspoof = DNSspoof()
    def test_dos(self):
        from pythem.modules.dos import DOSer
        dos = DOSer()
    def test_fuzzer(self):
        from pythem.modules.fuzzer import SimpleFuzz
        fuzzer = SimpleFuzz()
    def test_pforensic(self):
        from pythem.modules.pforensic import PcapReader
        pforensic = PcapReader()
    def test_scanner(self):
        from pythem.modules.scanner import Scanner
        scanner = Scanner()
    def test_sniffer(self):
        from pythem.modules.sniffer import Sniffer
        sniffer = Sniffer()
    def test_webcrawler(self):
        from pythem.modules.webcrawler import WebCrawler
        crawler = WebCrawler()
    def test_xploit(self):
        from pythem.modules.xploit import Exploit
        xploit = Exploit()
    def test_bruteforcer(self):
        from pythem.modules.bruteforcer import HashCracker, SSHbrutus, WEBbrutus
        hash_cracker = HashCracker()
        ssh_brute = SSHbrutus()
        web_brute = WEBbrutus()
    def test_utils(self):
        from pythem.modules.utils import decode
        from pythem.modules.utils import encode
        from pythem.modules.utils import credentials
        from pythem.modules.utils import credentials_harvest
        from pythem.modules.utils import banner
        from pythem.modules.utils import get_mymac
        from pythem.modules.utils import get_myip
        from pythem.modules.utils import pw_regex
        from pythem.modules.utils import user_regex
        from pythem.modules.utils import module_check
        from pythem.modules.utils import iptables
        from pythem.modules.utils import cookiedecode
        from pythem.modules.utils import set_ip_forwarding
        from pythem.modules.utils import print_help
    def test_interface(self):
        from pythem.core import interface

if __name__ == "__main__":
    unittest.main()
