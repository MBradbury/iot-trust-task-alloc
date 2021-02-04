#!/usr/bin/env python3

import os
import subprocess
import math
import pathlib

import numpy as np
import scipy.stats as stats

import matplotlib.pyplot as plt

from analysis.parser.edge_challenge_response import main as parse_cr
from analysis.graph.util import savefig

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def print_mean_ci(name, x, confidence=0.95):
    mean, sem, n = np.mean(x), stats.sem(x), len(x)
    print(name, mean, mean - stats.t.interval(0.95, len(x)-1, loc=np.mean(x), scale=stats.sem(x))[0])

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

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

    iterations = [
        cr.response.iterations
        for (hostname, result) in results.items()
        for cr in result.challenge_responses
    ]
    durations = [
        cr.response.duration
        for (hostname, result) in results.items()
        for cr in result.challenge_responses
    ]
    print_mean_ci("iterations", iterations)
    print_mean_ci("durations", durations)



    fig = plt.figure()
    ax = fig.gca()

    for (hostname, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        ax.scatter(X, Y, label=hostname)

    ax.set_xlabel('Iterations')
    ax.set_ylabel('Time Taken (secs)')

    ax.legend()

    savefig(fig, log_dir / "graphs" / "cr_iterations_vs_timetaken.pdf")

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

    savefig(fig, log_dir / "graphs" / "cr_iterations_boxplot.pdf")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Challenge Response')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
