#!/usr/bin/env python3

import os
from pprint import pprint
from ipaddress import IPv6Address
import pathlib

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.edge_challenge_response import main as parse_cr
from analysis.parser.wsn_pyterm import main as parse_pyterm
from analysis.graph.util import squash_true_false_seq, savefig

from common.names import hostname_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse_cr(log_dir)
    pyterm_results = parse_pyterm(log_dir)

    print([r.behaviour_changes for r in results.values()])

    if all(len(r.behaviour_changes) == 0 for r in results.values()):
        print("This graph type does not make sense for this result")
        return

    earliest = min(t for r in results.values() for (t, v) in r.behaviour_changes)
    latest = max(t for r in results.values() for (t, v) in r.behaviour_changes)

    # Find the latest time a task was submitted
    # Some times we might not have much behaviour changing to go on
    latest_task = max(t.time for r in pyterm_results.values() for t in r.tasks)

    latest = max(latest, latest_task)

    # Stacked bar graph showing how many tasks were offloaded to each node
    # over the time periods in which no changes occur

    # Create a graph showing when tasks where offloaded to nodes and that node was bad

    # Need to create some data ranges for well-behaved nodes, as they don't say when they are being bad
    event_types = {
        hostname_to_name(hostname): result.behaviour_changes + [(latest, result.behaviour_changes[-1][1])] if result.behaviour_changes else [(earliest, True), (latest, True)]
        for (hostname, result) in results.items()
    }

    # Calculate bins, need to include left edge of first bin and right edge of last bin
    bins = [t for (t, v) in event_types['rr6']]

    targets = {task.target for result in pyterm_results.values() for task in result.tasks}

    data = {
        target: [
            task.time
            for result in pyterm_results.values()
            for task in result.tasks
            if task.target == target
        ]
        for target in targets
    }

    fig = plt.figure()
    ax = fig.gca()

    y = 0
    yticks = []
    ytick_labels = []

    for (hostname, XY) in sorted(event_types.items(), key=lambda x: x[0]):
        true_list, false_list = squash_true_false_seq(XY)

        ax.broken_barh(true_list, (y,0.9), color="lightgreen")
        ax.broken_barh(false_list, (y,0.9), color="grey")

        yticks.append(y)
        ytick_labels.append(f"{hostname}")
        y += 1

    ax2 = ax.twinx()
    hlabels, hdata = zip(*list(sorted(data.items(), key=lambda x: x[0])))
    hlabels = [ip_to_name(l) for l in hlabels]
    ax2.hist(hdata, bins, stacked=True, histtype='bar', label=hlabels, rwidth=0.4)

    ax.set_yticks([x+0.45 for x in yticks])
    ax.set_yticklabels(ytick_labels)

    ax.set_xlabel('Time')
    ax.set_ylabel('Status')

    ax2.set_ylabel("Number of tasks submitted")

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax2.legend()

    savefig(fig, log_dir / "graphs" / "cr_offload_vs_behaviour.pdf")



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Offloading when bad')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
