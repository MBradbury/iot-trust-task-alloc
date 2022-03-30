#!/bin/bash
python3 -m tools.setup basic banded \
    --applications routing monitoring challenge-response \
    --target nRF52840DK \
    --deploy ansible \
    --with-pcap