#!/bin/bash 
(cd /home/libwandder && ./bootstrap.sh && ./configure LDFLAGS="-g" CFLAGS="-g" --prefix=/home/install/ && make && make install)