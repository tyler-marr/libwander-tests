#!/bin/bash

SUCCESS=success

if [ "$1" = "med" ]; then
	echo "Starting mediator..."
	openlimediator -c config/mediator-config.yaml
fi

if [ "$1" = "col" ]; then
	echo "Starting collector..."
	openlicollector -c config/collector-config-der.yaml
fi

if [ "$1" = "pro" ]; then
	echo "Starting provisioner..."
	openliprovisioner -c config/alushim-config.yaml
fi

if [ "$1" = "go" ]; then
	echo "Starting simple-count..."
	./simple-count etsilive:172.20.0.2:43332 3283 4591254 ALUSHIMTEST &
	TESTPID=$!
    sleep 5

	echo "Starting trace..."
	tracereplay traces/alushim.pcap ring:eth1
	sleep 10
	echo "...closing test"
    kill -TERM $TESTPID

	read -r line1 < /tmp/openli-test.out;
	if [[ $line1 != $SUCCESS ]]; then
		echo "FAILED"
		echo $line1
	else 
		echo "SUCCESS"
	fi
fi



