#!/bin/bash
python3 -m tools.setup basic banded \
    --applications monitoring routing \
    --target remote-revb \
    --deploy ansible \
    --with-pcap
