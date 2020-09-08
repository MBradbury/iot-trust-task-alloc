#!/bin/bash

# Stop anything currently running
pkill -9 python3

# Remove logs
rm -rf logs

rm -f nohup.out

nohup python3 -m tools.run.edge --application monitoring -2 --application routing 1 --application challenge_response -2 &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
