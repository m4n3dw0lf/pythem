import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

def run_test():
    from pythem.modules.redirect import Redirect
    print (u"  \u2714 Can import Redirect class")
    from pythem.modules.arpoisoner import ARPspoof
    print (u"  \u2714 Can import ARPspoof class")
    from pythem.modules.dhcpoisoner import DHCPspoof
    print (u"  \u2714 Can import DHCPspoof class")
    from pythem.modules.completer import Completer
    print (u"  \u2714 Can import Completer class")
    from pythem.modules.dnspoisoner import DNSspoof
    print (u"  \u2714 Can import DNSspoof class")
    from pythem.modules.dos import DOSer
    print (u"  \u2714 Can import DOSer class")
    from pythem.modules.fuzzer import SimpleFuzz
    print (u"  \u2714 Can import SimpleFuzz class")
    from pythem.modules.hashcracker import HashCracker
    print (u"  \u2714 Can import HashCracker class")
    from pythem.modules.pforensic import PcapReader
    print (u"  \u2714 Can import PcapReader class")
    from pythem.modules.scanner import Scanner
    print (u"  \u2714 Can import Scanner class")
    from pythem.modules.sniffer import Sniffer
    print (u"  \u2714 Can import Sniffer class")
    from pythem.modules.ssh_bruter import SSHbrutus
    print (u"  \u2714 Can import SSHBrutus class")
    from pythem.modules.web_bruter import WEBbrutus
    print (u"  \u2714 Can import WEBBrutus class")
    from pythem.modules.webcrawler import WebCrawler
    print (u"  \u2714 Can import WebCrawler class")
    from pythem.modules.xploit import Exploit
    print (u"  \u2714 Can import Exploit class")
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
    print (u"  \u2714 Can import utils functions")
    from pythem.core import interface
    print (u"  \u2714 Can import interface")

if __name__ == "__main__":
    try:
        print ("* Test: {}".format(__file__))
        a = run_test()
        print (u"\u2714 Test: {}".format(__file__))
    except Exception as e:
        print (u"\u2716 Test: {} failed, reason:".format(__file__))
        raise
