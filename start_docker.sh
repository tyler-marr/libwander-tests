#!/bin/bash

docker network rm wand-dev-replay
docker network create --driver bridge -o "com.docker.network.driver.mtu=9000" wand-dev-replay --subnet=172.20.0.0/16

docker container stop wand-dev
docker build -t wand-devtest -f ./Dockerfile .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d -P --rm -it --mount type=bind,source="$(pwd)"/..,target=/home --name wand-dev wand-devtest /bin/bash
docker network connect wand-dev-replay wand-dev
docker attach wand-dev 
