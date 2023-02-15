#!/bin/bash
python3 -m tools.setup throughput_pr badlisted_banded  \
    --applications routing monitoring \
    --target nRF52840DK \
    --deploy ansible \
    --with-pcap \
    --defines APPLICATIONS_MONITOR_THROUGHPUT 1 \
    --defines EXPECTED_TIME_THROUGHPUT_BAD 10 \
    --defines EXPECTED_TIME_THROUGHPUT_BAD_TO_GOOD_PR 0.6
