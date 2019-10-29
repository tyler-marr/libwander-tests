#!/bin/bash 
(cd /home/openli && ./bootstrap.sh && ./configure --prefix=/home/install/ CFLAGS="-I/home/install/include/ -g" LDFLAGS="-L/home/install/lib/ -g" && make && make install)
