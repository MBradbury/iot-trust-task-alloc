#!/bin/bash

INTERACTIVE=1

while getopts "d" flag
do
    case "${flag}" in
        d) INTERACTIVE=0;;
    esac
done

# Stop anything currently running
sudo pkill python3

# Remove logs
rm -rf logs
mkdir logs

# Cannot set negative niceness without running at higher privilege, so just use higher positive numbers to indicate
# a lower priority relative to each application.

nohup python3 -m tools.run.edge \
    --application bad_challenge_response 0 " --duration inf --approach random" \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

if [[ $INTERACTIVE == 1 ]]
then
    # Wait for nohup.out to be created
    sleep 1

    tail -f logs/$(hostname).nohup.out
fi
