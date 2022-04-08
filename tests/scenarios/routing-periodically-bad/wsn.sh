#!/bin/bash

source ./tests/common.sh

begin_test

rm -f nohup.out

nohup python3 -m tools.run.wsn \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

end_test
