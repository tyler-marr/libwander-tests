#!/bin/bash

SUCCESS=success

run_simple() {

    openlimediator start -c config/mediator-config.yaml &
    TESTMPID=$!
    openlicollector start -c config/collector-config.yaml &
    TESTCPID=$!
    openliprovisioner -c config/${1}-config.yaml &
    TESTPPID=$!
    
    ./simple-count etsilive:172.20.0.2:${2} ${3} ${4} ${5} &
    TESTPID=$!
    sleep 5

    tracereplay traces/${1}.pcap ring:eth1
    sleep 10
    kill -TERM $TESTPID
    kill -TERM $TESTMPID
    kill -TERM $TESTCPID
    kill -TERM $TESTPPID

    sleep 10

    read -r line1 < /tmp/openli-test.out;
    if [[ $line1 != $SUCCESS ]]; then
        echo "failing reason"
        echo \"$line1\"
        cat  /tmp/openli-test.out
       return 1
    fi
    

    return 0
}

echo "#####################Running ALU-shim tests"

# TODO remember number of RX queues so we can reset back to the
# original value after we're done

# TODO cap rxqueues to 1 to prevent RSS from messing up our tests

if ! run_simple alushim 43332 3283 4591254 ALUSHIMTEST; then
        sleep 10
        echo "Failed ALU-shim test"
        exit 1
fi

echo "################Running TCP SIP VOIP tests"

# Packets should really be 3950, but tracereplay is bursty and so
# we tend to miss the first few RTP packets because they're in sync
# with the SIP invite acceptance
if ! run_simple tcpsip 43332 3945 789000 TCPSIPTEST; then
        sleep 10
        echo "Failed TCP SIP VOIP test (CC)"
        exit 2
fi
echo "################Running TCP SIP VOIP tests2"
if ! run_simple tcpsip 44333 17 12182 TCPSIPTEST; then
        sleep 10
        echo "Failed TCP SIP VOIP test (IRI)"
        exit 3
fi

sleep 5
echo " "
echo "All tests passed."
echo " "

exit 0
