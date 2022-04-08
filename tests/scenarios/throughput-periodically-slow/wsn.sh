#!/bin/bash

INTERACTIVE=1

while getopts "d" flag
do
    case "${flag}" in
        d) INTERACTIVE=0;;
    esac
done

# Stop anything currently running
./tests/kill-test.sh

# Remove logs
rm -rf logs
mkdir logs

nohup python3 -m tools.run.wsn \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

if [[ $INTERACTIVE == 1 ]]
then
    # Wait for nohup.out to be created
    sleep 1

    tail -f logs/$(hostname).nohup.out
fi
