#!/bin/bash

source ./tests/common.sh

begin_test

# Cannot set negative niceness without running at higher privilege, so just use higher positive numbers to indicate
# a lower priority relative to each application.

nohup python3 -m tools.run.edge \
    --application monitoring 2 \
    --application routing 0 \
    --application challenge_response 1 \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

end_test
