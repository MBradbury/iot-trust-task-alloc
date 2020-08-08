#!/usr/bin/env python3

import os
import subprocess

import matplotlib.pyplot as plt

from analysis.parser.challenge_response_tm import main as parse_cr

edge_ids_to_names = {
    "00124b0014d52bd6": "edge-wsn2",
    "00124b0014d52f05": "edge-wsn6",
}

def main(log_dir):
    if not os.path.isdir("results/graphs"):
        os.makedirs("results/graphs")

    results = parse_cr(log_dir)

    edge_labels = {up.edge_id for result in results.values() for up in result.tm_updates}

    XYs = {
        (hostname, edge_ids_to_names[edge_label]): [
            (up.time, up.tm_to.epoch)
            for up
            in result.tm_updates
            if up.edge_id == edge_label
        ]
        for (hostname, result) in results.items()
        for edge_label in edge_labels
    }


    fig = plt.figure()
    ax = fig.gca()

    for (hostname, XY) in XYs.items():
        X, Y = zip(*XY)
        ax.step(X, Y, label=hostname)

    ax.set_xlabel('Time')
    ax.set_ylabel('Epoch Number')

    ax.legend()

    target = "results/graphs/cr_time_vs_epoch.pdf"
    fig.savefig(target, bbox_inches='tight')
    #subprocess.run(f"pdfcrop {target} {target}", shell=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Challenge Response')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
