#!/bin/bash

docker network rm openli-replay
docker network create --driver bridge -o "com.docker.network.driver.mtu=9000" openli-replay --subnet=172.20.0.0/16

docker container stop openli
docker build -t openlitest -f ./Dockerfile .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -d -P --rm -it --mount type=bind,source="$(pwd)"/..,target=/home --name openli openlitest /bin/bash
docker network connect openli-replay openli
docker attach openli 
