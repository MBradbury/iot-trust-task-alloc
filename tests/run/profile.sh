#!/bin/bash

source ./tests/common.sh

begin_test

nohup python3 -m tools.run.profile \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

end_test
