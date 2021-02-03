#!/usr/bin/env python3

import os
import pathlib
import itertools
from datetime import datetime

import pyshark.capture.inmem_capture
from pyshark.capture.inmem_capture import LinkTypes as LinkTypesBase, InMemCapture
from common.packet_log_processor import PacketLogProcessor

class LinkTypes(LinkTypesBase):
    IEEE802_15_4_NOFCS = 230

def main(source: pathlib.Path, dest: pathlib.Path, timeout: int):
    print(f"Converting {source} to {dest}")

    plp = PacketLogProcessor()
    with open(source, "r") as f:
        l, kinds, times = plp.process_all(f)

    custom_parameters = {"-w": str(dest)}

    # Set the timeout
    # TODO: Fix properly once https://github.com/KimiNewt/pyshark/pull/456 is merged
    pyshark.capture.inmem_capture.DEFAULT_TIMEOUT = timeout

    with InMemCapture(debug=True, linktype=LinkTypes.IEEE802_15_4_NOFCS, custom_parameters=custom_parameters) as cap:
        # This will not reassemble fragments into a single packet
        packets = cap.parse_packets(l, sniff_times=times)

        if len(packets) != len(kinds):
            raise RuntimeError("Invalid length")

    print(f"Finished converting {source} to {dest}!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Regenerate pcap files from the raw log')
    parser.add_argument('--source', type=pathlib.Path, required=True, help='The file which contains the raw pcap log output')
    parser.add_argument('--dest', type=pathlib.Path, required=True, help='The output pcap file')
    parser.add_argument('--timeout', type=int, default=600, help='The timeout in seconds')

    args = parser.parse_args()

    main(args.source, args.dest, args.timeout)
