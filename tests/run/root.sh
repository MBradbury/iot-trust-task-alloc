#!/bin/bash

# Stop anything currently running
pkill -9 python3

# Remove logs
rm -rf ~/iot-trust-task-alloc/logs

rm -f nohup.out

nohup ~/iot-trust-task-alloc/tools/run/root.py &

# Wait for nohup.out to be created
sleep 1

tail -f nohup.out
