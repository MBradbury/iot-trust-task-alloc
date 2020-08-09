#!/usr/bin/env python3

import os
import subprocess
from pprint import pprint
from collections import defaultdict

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.challenge_response_wsn import main as parse_cr

edge_ids_to_names = {
    "00124b0014d52bd6": "rr2",
    "00124b0014d52f05": "rr6",
}

def squash_true_false_seq(XY):
    """Return two lists containing a sequence of pairs of datetimes for which the value was true and false"""

    true_start = None
    false_start = None

    true_list = []
    false_list = []

    for (time, v) in XY:
        if v:
            # Transition from false to true
            if false_start is not None:
                false_list.append((false_start, time - false_start))
                false_start = None

            if true_start is None:
                true_start = time
        else:
            # Transition from true to false
            if true_start is not None:
                true_list.append((true_start, time - true_start))
                true_start = None

            if false_start is None:
                false_start = time

    # Transition from true to false
    if true_start is not None:
        true_list.append((true_start, time - true_start))
        true_start = None

    # Transition from false to true
    if false_start is not None:
        false_list.append((false_start, time - false_start))
        false_start = None

    return true_list, false_list



def main(log_dir):
    if not os.path.isdir(f"{log_dir}/graphs"):
        os.makedirs(f"{log_dir}/graphs")

    results = parse_cr(log_dir)

    edge_labels = {up.edge_id for result in results.values() for up in result.tm_updates}

    # Show how the epoch changes over time
    XYs = {
        (hostname, edge_ids_to_names[edge_label]): [
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
        ax.step(X, Y, label=hostname)

    ax.set_xlabel('Time')
    ax.set_ylabel('Epoch Number')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend()

    target = f"{log_dir}/graphs/cr_time_vs_epoch.pdf"
    fig.savefig(target, bbox_inches='tight')
    #subprocess.run(f"pdfcrop {target} {target}", shell=True)


    # Show when the edge nodes were thought to be good or not
    event_types = {
        (hostname, edge_ids_to_names[edge_label]): [
            (up.time, not up.tm_to.blacklisted)
            for up in result.tm_updates
            if up.edge_id == edge_label
        ]
        for (hostname, result) in results.items()
        for edge_label in edge_labels
    }

    event_cause = {
        (hostname, edge_ids_to_names[edge_label]): [
            (up.time, up.cr.kind)
            for up in result.tm_updates
            if up.edge_id == edge_label
            if not up.cr.good
            if up.tm_to.blacklisted
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

    for cevent in cxs:
        ax.scatter(cxs[cevent], cys[cevent], label=cevent)

    ax.set_yticks([x+0.45 for x in yticks])
    ax.set_yticklabels(ytick_labels)

    ax.set_xlabel('Time')
    ax.set_ylabel('Status')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    ax.legend()

    target = f"{log_dir}/graphs/cr_time_vs_good.pdf"
    fig.savefig(target, bbox_inches='tight')
    #subprocess.run(f"pdfcrop {target} {target}", shell=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Challenge Response')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
