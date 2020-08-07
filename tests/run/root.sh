#!/bin/bash

# Stop anything currently running
pkill -9 python3

# Remove logs
rm -rf ~/iot-trust-task-alloc/logs

rm nohup.out

nohup ~/iot-trust-task-alloc/tools/run/root.py &

tail -f nohup.out
