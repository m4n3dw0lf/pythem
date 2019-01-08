import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
import unittest
from netaddr import IPAddress
from scapy.all import *
from threading import Thread
from time import sleep
import os, sys

sys.stdout = open(os.devnull, 'w')

class TestMacTarget(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(TestMacTarget,self).__init__(group=group,name=name,verbose=verbose)
        self.args = args
        self.kwargs = kwargs
        return
    def test_sniffer_callback(self, p):
        if p.haslayer(ARP):
            if p[ARP].op == 1:
                socket = conf.L2socket(iface='lo')
                socket.send(Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ff:ff:ff:ff:ff') / ARP(op="is-at", pdst='127.0.0.1',
                                    psrc='127.0.0.1',hwdst="ff:ff:ff:ff:ff:ff",hwsrc='aa:bb:cc:dd:ee:ff'))
            if p[ARP].op == 2 and p[ARP].hwsrc == 'ff:ee:dd:cc:bb:aa':
                exit(0)
    def run(self):
        p = sniff(iface='lo', prn=self.test_sniffer_callback)
    
class TestARPspoofModule(unittest.TestCase):
    def test_arpspoof(self):
        from pythem.modules.utils import get_myip, get_mymac
        myip = get_myip('lo')
        mymac = get_mymac('lo')
        from pythem.modules.arpoisoner import ARPspoof
        arpspoof = ARPspoof()
        test_get_range = arpspoof.get_range('127.0.0.0/30')
        assert IPAddress('127.0.0.1') in test_get_range
        resolve_mac = TestMacTarget()
        resolve_mac.start()
        arpspoof.gateway = '127.0.0.10'
        arpspoof.interface = 'lo'
        arpspoof.myip = myip
        arpspoof.mymac = mymac
        sleep(1)
        test_resolve_mac = arpspoof.resolve_mac('127.0.0.1')
        assert test_resolve_mac == "aa:bb:cc:dd:ee:ff"
        arpspoof.start('10.0.0.1', None, 'lo', '10.0.0.10', 'ff:ee:dd:cc:bb:aa')
        resolve_mac.join()

if __name__ == "__main__":
    unittest.main()
