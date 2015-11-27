#!/bin/bash
# script to create freebsd tar package

./configure --prefix=/tmp/UD2
make install
tar -C /tmp -cjf /tmp/UniDomain.tar.bz2 UD2
#rm -rf /tmp/UD2
