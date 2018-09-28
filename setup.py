#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016-2018 Angelo Moura
#
# This file is part of the program pythem
#
# pythem is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA


from distutils.cmd import Command
from setuptools import setup

class TestCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def test(self):
        import os, sys, subprocess
        print ()
        tests = os.listdir('pythem/tests')
        for file in sorted(tests):
            if file.endswith('.py') and file != "full_test.py":
                new_test = subprocess.call([sys.executable, 'pythem/tests/'+file])
                if new_test != 0:
                    break

    def run(self):
        raise SystemExit(self.test())

setup(
    name='pythem',
    packages=['pythem','pythem/modules','pythem/core'],
    version='0.8.2',
    description="pentest framework",
    author='Angelo Moura',
    author_email='m4n3dw0lf@gmail.com',
    url='https://github.com/m4n3dw0lf/pythem',
    download_url='https://github.com/m4n3dw0lf/pythem/archive/0.8.1.tar.gz',
    keywords=['pythem', 'pentest', 'framework', 'hacking'],
    install_requires=['NetfilterQueue==0.8.1','pyOpenSSL>=16.2.0','decorator>=4.0.10','ecdsa>=0.13','mechanize>=0.2.5','netaddr>=0.7.18','requests>=2.10.0','scapy>=2.3.2','six>=1.10.0','update-checker>=0.11','cffi>=1.7.0','pycparser>=2.14','pyasn1>=0.1.9','paramiko>=2.0.1','capstone>=3.0.4','ropper>=1.10.7','termcolor>=1.1.0','psutil>=4.3.0'],
    dependency_links=[
        "git+git://git@github.com/kti/python-netfilterqueue@0.8.1#egg=NetfilterQueue-0.8.1"
    ],
    cmdclass=dict(test=TestCommand),
    scripts=['pythem/pythem'],
)
