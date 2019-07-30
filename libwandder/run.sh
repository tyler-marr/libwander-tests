#!/bin/bash

clear && ./update.sh && ./setup.sh && clear && valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all -v ./simple-count 1
#clear && ./update.sh && ./setup.sh && clear && gdb --args ./simple-count 1
#./simple-count
