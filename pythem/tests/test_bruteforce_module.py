import logging
logging.disable(logging.ERROR)
from multiprocessing.pool import ThreadPool
from mock import patch, mock_open
from paramiko import RSAKey
from time import sleep
import threading
import paramiko
import unittest
import socket
import os, sys 

sys.stdout = open(os.devnull, 'w')

host_key = RSAKey.generate(bits=4096)

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.authenticated = 0

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        logging.error("Credentials Received user: {} / password: {}".format(username,password))
        if username == "username" and password == "test_password":
            self.authenticated = 1
            return 0
	return 2

    def get_allowed_auths(self, username):
        return "password"

def listener():
    sock = socket.socket(2,1)
    sock.setsockopt(1,2,1)
    sock.bind(('',2222))
    sock.listen(100)
    client, addr = sock.accept()
    t = paramiko.Transport(client)
    t.add_server_key(host_key)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    server = Server()
    t.start_server(server=server)
    server.event.wait(3)
    t.close()
    return server.authenticated

pool = ThreadPool(processes=1)

class TestSSHModule(unittest.TestCase):
    def test_ssh_bruteforcer(self):
        from pythem.modules.bruteforcer import SSHbrutus
        async_result = pool.apply_async(listener,)
        bruter = SSHbrutus()
        with patch("__builtin__.open", mock_open(read_data="test_password")) as wordlist:
            bruter.start("127.0.0.1","username",wordlist,2222)
            return_val = async_result.get()
            assert return_val == 1
    def test_hash_bruteforcer(self):
        from pythem.modules.bruteforcer import HashCracker
        bruter = HashCracker()
        bruter.type = "md5"
        with patch("__builtin__.open", mock_open(read_data="test_password\n")) as wordlist: 
            result = bruter.hashcrack(hash="1a4d7a1d27600bdb006f9d126a4c4a81",wordlist=wordlist)
            assert result.startswith("[+] MD5 Cracked: test_password")

if __name__ == "__main__":
    unittest.main()
