import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import unittest

class TestModuleImports(unittest.TestCase):
    def test_redirect_import(self):
        from pythem.modules.redirect import Redirect
    def test_arpspoof_import(self):
        from pythem.modules.arpoisoner import ARPspoof
    def test_dhcpspoof_import(self):
        from pythem.modules.dhcpoisoner import DHCPspoof
    def test_completer_import(self):
        from pythem.modules.completer import Completer
    def test_dnsspoof_import(self):
        from pythem.modules.dnspoisoner import DNSspoof
    def test_dos_import(self):
        from pythem.modules.dos import DOSer
    def test_fuzzer_import(self):
        from pythem.modules.fuzzer import SimpleFuzz
    def test_cracker_import(self):
        from pythem.modules.hashcracker import HashCracker
    def test_pforensic_import(self):
        from pythem.modules.pforensic import PcapReader
    def test_scanner_import(self):
        from pythem.modules.scanner import Scanner
    def test_sniffer_import(self):
        from pythem.modules.sniffer import Sniffer
    def test_sshbrute_import(self):
        from pythem.modules.ssh_bruter import SSHbrutus
    def test_webbrute_import(self):
        from pythem.modules.web_bruter import WEBbrutus
    def test_webcrawler_import(self):
        from pythem.modules.webcrawler import WebCrawler
    def test_xploit_import(self):
        from pythem.modules.xploit import Exploit
    def test_utils_functions(self):
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
    def test_interface_import(self):
        from pythem.core import interface

if __name__ == "__main__":
    unittest.main()
