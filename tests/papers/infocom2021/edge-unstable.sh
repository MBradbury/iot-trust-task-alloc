#!/bin/bash

source ./tests/common.sh

begin_test

# Cannot set negative niceness without running at higher privilege, so just use higher positive numbers to indicate
# a lower priority relative to each application.

nohup python3 -m tools.run.edge \
    --application bad_challenge_response 0 " --duration inf --approach random" \
    </dev/null >logs/$(hostname).nohup.out 2>&1 &

end_test
