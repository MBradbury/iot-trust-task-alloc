#!/usr/bin/env python3

import pathlib
from pprint import pprint

import numpy as np

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.wsn_pyterm import main as parse, LastPing
from analysis.graph.util import savefig

from common.names import ip_to_name, eui64_to_name, hostname_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def main(log_dir: pathlib.Path, throw_on_error: bool=True):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse(log_dir, throw_on_error=throw_on_error)

    targets = {
        value.edge_id

        for result
        in results.values()

        for value
        in result.tm_updates
        if isinstance(value.cr, LastPing)
    }

    XYs = {
        (hostname, target): [
            (value.time, value.tm_to.ping - value.tm_from.ping)
            for value
            in result.tm_updates
            if isinstance(value.cr, LastPing)
            if value.edge_id == target
        ]

        for (hostname, result)
        in results.items()

        for target in targets
    }

    fig = plt.figure()
    ax = fig.gca()

    for (label, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        hostname, target = label

        if not XY:
            print(f"Skipping {label}")
            continue

        X, Y = zip(*XY)
        ax.plot(X, Y, label=f"{hostname_to_name(hostname)} eval {eui64_to_name(target)}")

    ax.set_xlabel('Time')
    ax.set_ylabel('Time between pings (ms)')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend(ncol=3, fontsize="small", loc="center", bbox_to_anchor=(0.5,1.075))

    savefig(fig, f"{log_dir}/graphs/time_between_pings.pdf")



    fig = plt.figure()
    ax = fig.gca()

    Xs = []
    labels = []

    for (label, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        hostname, target = label

        if not XY:
            print(f"Skipping {label}")
            continue

        _, Y = zip(*XY)

        Xs.append(Y)
        labels.append(f"{hostname_to_name(hostname)} eval {eui64_to_name(target)}")

    ax.hist(Xs, stacked=True)

    ax.set_xlabel('Time between pings (ms)')
    ax.set_ylabel('Count')

    savefig(fig, f"{log_dir}/graphs/time_between_pings_hist.pdf")



    fig = plt.figure()
    ax = fig.gca()

    Xs = []
    labels = []

    for (label, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        hostname, target = label

        if not XY:
            print(f"Skipping {label}")
            continue

        _, Y = zip(*XY)

        Xs.append(Y)
        labels.append(f"{hostname_to_name(hostname)} eval {eui64_to_name(target)}")

    ax.boxplot(Xs, labels=labels)

    ax.set_xlabel('Target')
    ax.set_ylabel('Time between pings (ms)')

    ax.set_xticklabels(labels, rotation=45)

    savefig(fig, f"{log_dir}/graphs/time_between_pings_boxplot.pdf")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Time between pings')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')
    parser.add_argument('--continue-on-error', action="store_true", default=False, help='Should bad lines be skipped')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir, not args.continue_on_error)
