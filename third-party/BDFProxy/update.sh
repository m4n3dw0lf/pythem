#!/bin/bash
echo 'Updating BDFProxy'
git pull
echo 'Updating BDF'
cd bdf/
git pull origin master
./install.sh
