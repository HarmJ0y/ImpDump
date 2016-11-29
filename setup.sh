#!/bin/bash

echo 'Downloading Impacket...'

git clone https://github.com/CoreSecurity/impacket.git /tmp/impacket-git/

echo 'Installing Impacket...'
cd /tmp/impacket-git/
python setup.py install
cd -

echo 'Done!'
