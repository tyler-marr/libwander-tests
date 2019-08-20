#!/bin/bash 
(cd /home/wandio && ./bootstrap.sh && ./configure LDFLAGS="-g" CFLAGS="-g" --prefix=/home/install/ && make && make install)
