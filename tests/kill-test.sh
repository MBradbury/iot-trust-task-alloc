#!/bin/bash
if [ -f pidfile ]
then
    while IFS="" read -r line || [ -n "$line" ]
    do
        echo "Killing $line and children"
        rkill $1 $line
    done <pidfile
    #rm pidfile
fi

exit 0
