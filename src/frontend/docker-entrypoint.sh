#!/bin/bash

if [ "$1" = "loop" ]
then
    sh -c "while true; do sleep 1; done"
else
    /src/server
fi