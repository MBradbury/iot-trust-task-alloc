#!/bin/bash
python3 -m tools.setup basic_with_reputation banded \
    --applications routing monitoring \
    --target remote-revb \
    --deploy ansible \
    --with-pcap \
    --with-adversary dos_certificate_verification
