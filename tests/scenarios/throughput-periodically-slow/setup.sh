#!/bin/bash
python3 -m tools.setup throughput banded \
    --applications routing monitoring challenge-response \
    --target nRF52840DK \
    --deploy ansible \
    --with-pcap \
    --defines APPLICATIONS_MONITOR_THROUGHPUT 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL 10