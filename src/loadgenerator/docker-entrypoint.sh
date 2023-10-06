#!/bin/bash

if [ -z $2 ]
then
    debug="info"
else
    debug=$2
fi

if [ "$1" = "loop" ]
then
    sh -c "while true; do sleep 1; done"
elif [ "$1" = "start" ]
then
    locust --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
elif [ "$1" = "freeship" ]
then
    locust --locustfile locustfileShipUsr.py --logfile loadgenShipUsr.log --loglevel $debug --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
elif [ "$1" = "robocost" ]
then
    locust --locustfile locustfileRoboCost.py --logfile loadgenRoboCost.log --loglevel $debug --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
fi
