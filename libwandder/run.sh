#!/bin/bash

#valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all -v ./simple-count
gdb --args ./simple-count
#./simple-count