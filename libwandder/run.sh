#!/bin/bash

#valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all -v ./simple-count 1
gdb --args ./simple-count 1
#./simple-count
