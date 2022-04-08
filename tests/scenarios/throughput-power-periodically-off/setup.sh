#!/bin/bash
python3 -m tools.setup throughput banded \
    --applications routing monitoring \
    --target nRF52840DK \
    --deploy ansible \
    --with-pcap \
    --with-bad-edge radio_off \
    --defines APPLICATIONS_MONITOR_THROUGHPUT 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL 10 \
    --defines EDGE_ATTACK_RADIO_OFF_INTERVAL 300 \
    --defines EDGE_ATTACK_RADIO_OFF_DURATION 5
