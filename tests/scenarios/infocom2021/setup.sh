#!/bin/bash
python3 -m tools.setup basic banded \
    --applications challenge-response \
    --target remote-revb \
    --deploy ansible \
    --with-pcap
