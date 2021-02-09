#!/usr/bin/env python3
from __future__ import annotations

import pathlib

from pyshark.capture.inmem_capture import LinkTypes as LinkTypesBase, InMemCapture
from common.packet_log_processor import PacketLogProcessor

class LinkTypes(LinkTypesBase):
    IEEE802_15_4_NOFCS = 230

def main(source: pathlib.Path, dest: pathlib.Path, timeout: Optional[int]):
    print(f"Converting {source} to {dest}")

    plp = PacketLogProcessor()
    with open(source, "r") as f:
        l, kinds, times = plp.process_all(f)

    custom_parameters = {"-w": str(dest)}

    with InMemCapture(debug=True, linktype=LinkTypes.IEEE802_15_4_NOFCS, custom_parameters=custom_parameters) as cap:
        # This will not reassemble fragments into a single packet
        packets = cap.parse_packets(l, sniff_times=times, timeout=timeout)

        if len(packets) != len(kinds):
            raise RuntimeError("Invalid length")

    print(f"Finished converting {source} to {dest}!")

def int_or_None(arg: str) -> Optional[int]:
    try:
        return int(arg)
    except ValueError:
        if arg == "None":
            return None
        else:
            raise

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Regenerate pcap files from the raw log')
    parser.add_argument('--source', type=pathlib.Path, required=True, help='The file which contains the raw pcap log output')
    parser.add_argument('--dest', type=pathlib.Path, required=True, help='The output pcap file')
    parser.add_argument('--timeout', type=int_or_None, default=600, help='The timeout in seconds, pass "None" for no timeout.')

    args = parser.parse_args()

    main(args.source, args.dest, args.timeout)
