#!/bin/bash

docker exec -it --user $(id -u):$(id -g) wand-dev /bin/bash
