#!/bin/bash

# Stop anything currently running
sudo pkill python3

# Remove logs
rm -rf logs

rm -f nohup.out

# Cannot set negative niceness without running at higher privilege, so just use higher positive numbers to indicate
# a lower priority relative to each application.

nohup python3 -m tools.run.bad_edge --application monitoring 2 --application routing 0 --application challenge_response 1 &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
