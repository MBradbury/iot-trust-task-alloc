#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import multiprocessing.pool

import regenerate_pcap

def main(directory: pathlib.Path, num_procs: int, timeout: Optional[int]):
    sources = list(directory.glob("*.packet.log"))
    destinations = [src.parent / (src.name + '.pcap') for src in sources]

    args = list(zip(sources, destinations, [timeout]*len(sources)))

    print(f"Generating pcaps for {sources}")
    print(f"using {num_procs} processes")

    with multiprocessing.pool.Pool(num_procs) as pool:
        pool.starmap(regenerate_pcap.main, args)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Regenerate pcap files from the raw log')
    parser.add_argument('directory', type=pathlib.Path, help='The directory containing multiple pcap logs to convert')
    parser.add_argument('--num-procs', type=int, required=False, default=len(os.sched_getaffinity(0)), help='The number of processes to use')
    parser.add_argument('--timeout', type=regenerate_pcap.int_or_None, default=600, help='The timeout per file in seconds. pass "None" for no timeout.')

    args = parser.parse_args()

    main(args.directory, args.num_procs, args.timeout)
