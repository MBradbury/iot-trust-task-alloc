#!/bin/bash
if [ -f pidfile ]
then
    cat pidfile | xargs kill -9
    rm pidfile
fi
