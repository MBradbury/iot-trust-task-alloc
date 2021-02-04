#!/usr/bin/env python3

import os
from pprint import pprint
from ipaddress import IPv6Address
from more_itertools import pairwise
import itertools
import pathlib

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.edge_challenge_response import main as parse_cr
from analysis.parser.wsn_pyterm import main as parse_pyterm
from analysis.graph.util import squash_generic_seq, savefig

from common.names import hostname_to_name, eui64_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def find_status_at_time(status, t):
    # All pairs of changes
    for ((at, av), (bt, bv)) in pairwise(status):
        if t >= at and t < bt:
            return av

    if t >= status[-1][0]:
        return status[-1][1]

    # Unknown
    return None

def belief_correct(belief, actual):
    # These lists contain the times at which the status changed

    # All the times belief or actual status changed
    changes = list(sorted(list(zip(*belief))[0] + list(zip(*actual))[0]))

    result = []

    for t in changes:
        # Find the actual value at this time
        a = find_status_at_time(actual, t)
        b = find_status_at_time(belief, t)

        r = None

        if a is None or b is None:
            r = None

        # Correct
        elif a and b:
            r = "TP"

        elif not a and not b:
            r = "TN"

        # Incorrect, believed to be bad
        elif a and not b:
            r = "FN"

        # Incorrect believed to be good
        elif not a and b:
            r = "FP"

        result.append((t, r))

    return result


def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse_cr(log_dir)
    pyterm_results = parse_pyterm(log_dir)

    print([r.behaviour_changes for r in results.values()])

    earliest = min(t for r in results.values() for (t, v) in r.behaviour_changes)
    latest = max(t for r in results.values() for (t, v) in r.behaviour_changes)

    # Find the latest time a task was submitted
    # Some times we might not have much behaviour changing to go on
    latest_task = max(t.time for r in pyterm_results.values() for t in r.tasks)

    latest = max(latest, latest_task)

    # Create a graph showing when tasks where offloaded to nodes and that node was bad

    # Need to create some data ranges for well-behaved nodes, as they don't say when they are being bad
    actual = {
        hostname_to_name(hostname): result.behaviour_changes + [(latest, result.behaviour_changes[-1][1])] if result.behaviour_changes else [(earliest, True), (latest, True)]
        for (hostname, result) in results.items()
    }

    edge_labels = {up.edge_id for result in pyterm_results.values() for up in result.tm_updates}
    belived = {
        (hostname, eui64_to_name(edge_label)): [
            (up.time, not up.tm_to.bad)
            for up in result.tm_updates
            if up.edge_id == edge_label
        ]
        for (hostname, result) in pyterm_results.items()
        for edge_label in edge_labels
    }

    # Translate believed into whether the belief was correct or not
    correct = {
        (wsn, edge): belief_correct(results, actual[edge])
        for ((wsn, edge), results) in belived.items()
    }

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

    legend = True

    x = plt.cm.get_cmap('tab10')

    # new tab10
    """tp_colour = "#59a14f"
    tn_colour = "#4e79a7"
    fp_colour = "#b07aa1"
    fn_colour = "#9c755f"
    u_colour = "#bab0ac"""

    tp_colour = x(2)
    tn_colour = x(0)
    fp_colour = x(4)
    fn_colour = x(5)
    u_colour = x(7)

    summaries = {}

    for (hostname, XY) in sorted(correct.items(), key=lambda x: x[0]):
        result = squash_generic_seq(XY, ("TP", "TN", "FP", "FN", None))

        summary = {k: sum(v[1].total_seconds() for v in vv) for (k, vv) in result.items() if k is not None}
        summary_total = sum(summary.values())
        summary_pc = {k: round(v/summary_total, 2) for (k, v) in summary.items()}
        print(hostname, summary_pc)

        summaries[hostname] = f"\\ConfusionMatrix{{{summary_pc['TP']}}}{{{summary_pc['TN']}}}{{{summary_pc['FP']}}}{{{summary_pc['FN']}}}"

        ax.broken_barh(result["TP"], (y,0.9), color=tp_colour, label="TP" if legend else None)
        ax.broken_barh(result["TN"], (y,0.9), color=tn_colour, label="TN" if legend else None)
        ax.broken_barh(result["FP"], (y,0.9), color=fp_colour, label="FP" if legend else None)
        ax.broken_barh(result["FN"], (y,0.9), color=fn_colour, label="FN" if legend else None)
        #ax.broken_barh(result[None], (y,0.9), color=u_colour, label="U" if legend else None)

        yticks.append(y)
        ytick_labels.append(f"{hostname[0]}\\newline eval {hostname[1]}")
        y += 1

        legend = False

    ax.set_yticks([x+0.45 for x in yticks])
    ax.set_yticklabels(ytick_labels)

    ax.set_xlabel('Time')
    ax.set_ylabel('Status')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend()

    savefig(fig, log_dir / "graphs" / "cr_correctly_evaluated.pdf")


    print("\\begin{table}[H]")
    wsns = list(sorted({k[0] for k in summaries.keys()}))
    rrs = list(sorted({k[1] for k in summaries.keys()}))

    print("\\centering")
    print("\\begin{tabular}{l c c c}")

    print(" & ".join(['~'] + wsns) + "\\\\")

    for rr in rrs:
        print(rr)
        for wsn in wsns:
            summary = summaries[(wsn, rr)]

            print("&", summary)
        print("\\\\")

    print("\\end{tabular}")
    print("\\end{table}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Correctly Evaluated')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
