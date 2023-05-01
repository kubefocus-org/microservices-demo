#!/bin/bash

if [ "$1" = "loop" ]
then
    sh -c "while true; do sleep 1; done"
else
    locust --host="http://${FRONTEND_ADDR}" --headless -u "${USERS:-10}" 2>&1
fi