#!/bin/bash
python3 -m tools.setup throughput banded \
    --applications routing monitoring challenge-response \
    --target nRF52840DK \
    --deploy ansible \
    --with-pcap \
    --with-adversary dos_target_network \
    --defines APPLICATIONS_MONITOR_THROUGHPUT 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING 1 \
    --defines TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL 10 \
    --defines DOS_ADDRESS 'CC_STRINGIFY(fd00::f6ce:3646:7fb7:cac7)' \
    --defines DOS_PERIOD_MS 20 \
    --defines ATTACK_RADIO_OFF_INTERVAL 300 \
    --defines ATTACK_RADIO_OFF_DURATION 5
