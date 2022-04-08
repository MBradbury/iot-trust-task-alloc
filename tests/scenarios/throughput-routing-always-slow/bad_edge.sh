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
    --application monitoring 2 \
    --application bad_routing 0 " --approach slow --duration inf --slow-wait 1" \
    --application challenge_response 1 \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

if [[ $INTERACTIVE == 1 ]]
then
    # Wait for nohup.out to be created
    sleep 1

    tail -f logs/$(hostname).nohup.out
fi
