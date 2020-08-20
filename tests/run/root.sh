#!/bin/bash

# Stop anything currently running
pkill -9 python3
pkill -9 tunslip6

# Remove logs
rm -rf logs

rm -f nohup.out

nohup nohup python3 -m tools.run.root &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
