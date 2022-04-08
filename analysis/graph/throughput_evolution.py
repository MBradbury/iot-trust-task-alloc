#!/usr/bin/env python3

import pathlib
from pprint import pprint

import numpy as np

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.wsn_pyterm import main as parse, ThroughputDirection
from analysis.graph.util import savefig

from common.names import ip_to_name, eui64_to_name, hostname_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse(log_dir)

    capabilities = {
        value.capability

        for result
        in results.values()

        for value
        in result.trust_choose.values
    }

    targets = {
        value.target

        for result
        in results.values()

        for value
        in result.trust_choose.values
    }

    CXYs = {
        (capability, direction): {
            (hostname, target): [
                (value.time, value.cr.throughput)
                for value
                in result.throughput_updates
                if value.edge_id == target
                if value.cr.capability == capability
                if value.cr.direction == direction
            ]

            for (hostname, result)
            in results.items()

            for target in targets
            
        }

        for capability in capabilities
        for direction in ThroughputDirection
    }

    # TODO: Draw some bar graphs of which nodes tasks were submitted to

    for ((capability, direction), XYs) in CXYs.items():
        fig = plt.figure()
        ax = fig.gca()

        for (label, XY) in sorted(XYs.items(), key=lambda x: x[0]):
            hostname, target = label

            if not XY:
                print(f"Skipping {label}")
                continue

            X, Y = zip(*XY)
            ax.plot(X, Y, label=f"{hostname_to_name(hostname)} eval {eui64_to_name(target)} dir {direction}")

        ax.set_xlabel('Time')
        ax.set_ylabel('Throughput (bytes/sec)')

        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

        ax.legend(ncol=3, fontsize="small", loc="center", bbox_to_anchor=(0.5,1.075))

        savefig(fig, f"{log_dir}/graphs/throughput_vs_time_{capability}_{direction}.pdf")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Throughput Value Over Time')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
