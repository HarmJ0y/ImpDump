#!/bin/bash

echo 'Downloading Impacket...'

svn checkout http://impacket.googlecode.com/svn/trunk/ /tmp/impacket-svn/

echo 'Installing Impacket...'
cd /tmp/impacket-svn/
python setup.py install
cd -

echo 'Done!'
