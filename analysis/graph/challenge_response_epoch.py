#!/usr/bin/env python3

import os
import subprocess
from pprint import pprint
from collections import defaultdict
import pathlib

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.wsn_pyterm import main as parse_cr
from analysis.graph.util import squash_true_false_seq, ChallengeResponseType_to_shape_and_color, latex_escape, savefig

from common.names import eui64_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse_cr(log_dir)

    edge_labels = {up.edge_id for result in results.values() for up in result.tm_updates}

    # Show how the epoch changes over time
    XYs = {
        (hostname, eui64_to_name(edge_label)): [
            (up.time, up.tm_to.epoch)
            for up in result.tm_updates
            if up.edge_id == edge_label
        ]
        for (hostname, result) in results.items()
        for edge_label in edge_labels
    }


    fig = plt.figure()
    ax = fig.gca()

    for (hostname, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        ax.step(X, Y, label=f"{hostname[0]} evaluating {hostname[1]}")

    ax.set_xlabel('Time')
    ax.set_ylabel('Epoch Number')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend()

    savefig(fig, log_dir / "graphs" / "cr_time_vs_epoch.pdf")


    # Show when the edge nodes were thought to be good or not
    event_types = {
        (hostname, eui64_to_name(edge_label)): [
            (up.time, not up.tm_to.bad)
            for up in result.tm_updates
            if up.edge_id == edge_label
        ]
        for (hostname, result) in results.items()
        for edge_label in edge_labels
    }

    event_cause = {
        (hostname, eui64_to_name(edge_label)): [
            (up.time, up.cr.kind)
            for up in result.tm_updates
            if up.edge_id == edge_label
            if not up.cr.good
            if up.tm_to.bad
        ]
        for (hostname, result) in results.items()
        for edge_label in edge_labels
    }

    #pprint(event_cause)

    fig = plt.figure()
    ax = fig.gca()

    y = 0
    yticks = []
    ytick_labels = []

    cxs = defaultdict(list)
    cys = defaultdict(list)

    for (hostname, XY) in sorted(event_types.items(), key=lambda x: x[0]):
        true_list, false_list = squash_true_false_seq(XY)

        ax.broken_barh(true_list, (y,0.9), color="lightgreen")
        ax.broken_barh(false_list, (y,0.9), color="grey")

        # Record the causes of these changes
        causes = event_cause[hostname]
        for (ctime, cevent) in causes:
            cxs[cevent].append(ctime)
            cys[cevent].append(y + 0.45)

        yticks.append(y)
        ytick_labels.append(f"{hostname[0]}\neval {hostname[1]}")
        y += 1

    for cevent in sorted(cxs):
        (shape, colour) = ChallengeResponseType_to_shape_and_color(cevent)

        ax.scatter(cxs[cevent], cys[cevent], label=latex_escape(cevent), c=colour, marker=shape)

    ax.set_yticks([x+0.45 for x in yticks])
    ax.set_yticklabels(ytick_labels)

    ax.set_xlabel('Time')
    ax.set_ylabel('Status')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend()

    savefig(fig, log_dir / "graphs" / "cr_time_vs_good.pdf")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Challenge Response')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
