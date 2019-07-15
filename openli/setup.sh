#!/bin/bash


gcc -g -Wall -o simple-count simple-count.c -I/home/install/include/ -L/home/install/lib/ -ltrace -lwandder 
