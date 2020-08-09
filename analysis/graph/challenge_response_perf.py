#!/usr/bin/env python3

import os
import subprocess

import matplotlib.pyplot as plt

from analysis.parser.edge_challenge_response import main as parse_cr

def main(log_dir):
    if not os.path.isdir(f"{log_dir}/graphs"):
        os.makedirs(f"{log_dir}/graphs")

    results = parse_cr(log_dir)

    XYs = {
        hostname: [
            (cr.response.iterations, cr.response.duration)
            for cr
            in result.challenge_responses
        ]
        for (hostname, result)
        in results.items()
    }


    fig = plt.figure()
    ax = fig.gca()

    for (hostname, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        ax.scatter(X, Y, label=hostname)

    ax.set_xlabel('Iterations')
    ax.set_ylabel('Time Taken (secs)')

    ax.legend()

    target = f"{log_dir}/graphs/cr_iterations_vs_timetaken.pdf"
    fig.savefig(target, bbox_inches='tight')
    #subprocess.run(f"pdfcrop {target} {target}", shell=True)


    fig = plt.figure()
    ax = fig.gca()

    Xs = []
    labels = []

    for (hostname, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        Xs.append(X)
        labels.append(hostname)
    
    ax.boxplot(Xs)
    ax.set_xticklabels(labels)

    ax.set_xlabel('Resource Rich Nodes')
    ax.set_ylabel('Iterations')

    target = f"{log_dir}/graphs/cr_iterations_boxplot.pdf"
    fig.savefig(target, bbox_inches='tight')
    #subprocess.run(f"pdfcrop {target} {target}", shell=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Challenge Response')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
