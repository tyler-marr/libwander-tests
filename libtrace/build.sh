#!/bin/bash 
(cd /home/libtrace && ./bootstrap.sh && ./configure LDFLAGS="-g -L/home/install/lib" CFLAGS="-g -I/home/install/include" --prefix=/home/install/ && make && make install)
