#!/bin/bash

# Stop anything currently running
sudo pkill -9 python3
sudo pkill -9 tunslip6

# Remove logs
rm -rf logs

rm -f nohup.out

nohup python3 -m tools.run.root &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
