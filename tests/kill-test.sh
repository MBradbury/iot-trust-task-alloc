#!/bin/bash
if [ -f pidfile ]
then
    cat pidfile | xargs rkill -9
    #rm pidfile
fi
