#!/bin/bash
python3 -m tools.setup throughput_pr banded \
    --applications routing monitoring \
    --target nRF52840DK \
    --deploy ansible \
    --defines APPLICATIONS_MONITOR_THROUGHPUT 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL 10
