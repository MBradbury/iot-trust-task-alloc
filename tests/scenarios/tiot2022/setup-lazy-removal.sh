#!/bin/bash
python3 -m tools.setup basic_with_reputation banded \
    --applications routing monitoring \
    --target remote-revb \
    --deploy ansible \
    --with-pcap \
    --defines BAND_SIZE 0.5f \
    --defines NO_ACTIVE_REMOVAL_ON_UNANNOUNCE 1
