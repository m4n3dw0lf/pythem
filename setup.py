from distutils.core import setup

setup(
    name='pythem',
    packages=['pythem','pythem/modules','pythem/core'],
    version='0.7.7',
    description="pentest framework",
    author='Angelo Moura',
    author_email='m4n3dw0lf@gmail.com',
    url='https://github.com/m4n3dw0lf/pythem',
    download_url='https://github.com/m4n3dw0lf/pythem/archive/0.7.7.tar.gz',
    keywords=['pythem', 'pentest', 'framework', 'hacking'],
    install_requires=['NetfilterQueue==0.8.1','pyOpenSSL>=16.2.0','decorator>=4.0.10','ecdsa>=0.13','mechanize>=0.2.5','netaddr>=0.7.18','requests>=2.10.0','scapy>=2.3.2','six>=1.10.0','update-checker>=0.11','cffi>=1.7.0','pycparser>=2.14','pyasn1>=0.1.9','paramiko>=2.0.1','capstone>=3.0.4','ropper>=1.10.7','termcolor>=1.1.0','psutil>=4.3.0'],
    dependency_links=[
        "git+git://git@github.com/kti/python-netfilterqueue@0.8.1#egg=NetfilterQueue-0.8.1"
    ],
    scripts=['pythem/pythem'],
)
