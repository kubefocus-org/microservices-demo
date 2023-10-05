#!/bin/bash

if [ "$1" = "loop" ]
then
    sh -c "while true; do sleep 1; done"
else if [ "$1" = "start" ]
then
    locust --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
else if [ "$1" = "freeship" ]
then
    locust --locustfile locustfileShipUsr.py --logfile loadgenShipUsr.log --loglevel info --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
else if [ "$1" = "robocost" ]
then
    locust --locustfile locustfileRoboCost.py --logfile loadgenRoboCost.log --loglevel info --host="http://${AUTHSERVICE_ADDR}" --headless -u "${USERS:-10}" 2>&1
fi
