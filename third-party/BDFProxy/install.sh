#!/bin/bash
git submodule init
git submodule update

pip install configobj
./update.sh
