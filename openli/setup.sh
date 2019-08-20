#!/bin/bash


gcc -g -Wall simple-count.c -I/home/install/include/ -L/home/install/lib/ -ltrace -lwandder -o simple-count
