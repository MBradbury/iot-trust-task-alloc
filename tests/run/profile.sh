#!/bin/bash

# Stop anything currently running
pkill -9 python3

nohup python3 -m tools.run.profile &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
