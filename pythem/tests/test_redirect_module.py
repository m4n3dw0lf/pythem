import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
import os,sys
import requests

sys.stdout = open(os.devnull, 'w')

import unittest
from time import sleep

class TestModulesObjectsCreation(unittest.TestCase):
    def test_redirect_startup(self):
        from pythem.modules.utils import get_myip
        myip = get_myip('lo')
        from pythem.modules.redirect import Redirect
        redirect = Redirect()
        redirect.dnsspoof = None
        redirect.js = "<script>window.location.href='http://localhost:8080/test'</script>"
        redirect.start(myip, 8080, 'test.js')
        first_req = requests.get("http://localhost:8080")
        assert "test.js" in first_req.text
        assert first_req.status_code == 200
        redirected = requests.get("http://localhost:8080")
        assert redirected.text == '<body><meta http-equiv="refresh" content="0; url=http://localhost"/></body>'
        assert redirected.status_code == 200

if __name__ == "__main__":
    unittest.main()
