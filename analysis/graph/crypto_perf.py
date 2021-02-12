#!/usr/bin/env python3

import os
import subprocess
import math
import pathlib

import numpy as np
import scipy.stats as stats

import matplotlib.pyplot as plt

from analysis.parser.profile_pyterm import main as profile_pyterm
from analysis.graph.util import savefig

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def print_mean_ci(name, x, confidence=0.95):
    mean, sem, n = np.mean(x), stats.sem(x), len(x)
    print(name, mean, mean - stats.t.interval(0.95, len(x)-1, loc=np.mean(x), scale=stats.sem(x))[0])

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = profile_pyterm(log_dir)

    XYs = {
        hostname: [
            (cr.length, cr.seconds)
            for cr
            in result.stats_sha256
        ]
        for (hostname, result)
        in results.items()
    }



    fig = plt.figure()
    ax = fig.gca()

    for (hostname, XY) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        ax.scatter(X, Y, label=hostname)

    ax.set_xlabel('Message Length')
    ax.set_ylabel('Time Taken (secs)')

    ax.legend()

    savefig(fig, log_dir / "graphs" / "crypto_perf_sha256_scatter.pdf")


    


    fig = plt.figure()
    ax = fig.gca()

    Ys = []
    labels = []

    for (hostname, result) in sorted(XYs.items(), key=lambda x: x[0]):
        X, Y = zip(*XY)
        Ys.append(Y)
        labels.append(hostname)
    
    ax.boxplot(Ys)
    ax.set_xticklabels(labels)

    ax.set_xlabel('Resource Rich Nodes')
    ax.set_ylabel('Time Taken (secs)')

    savefig(fig, log_dir / "graphs" / "crypto_perf_sha256_box.pdf")


    def round_down(x: float, a: float) -> float:
        return math.floor(x / a) * a

    def round_up(x: float, a: float) -> float:
        return math.ceil(x / a) * a


    names = {
        "stats_sha256_u": 1e-5,
        "stats_sha256_n": 1e-7,
        "stats_ecdh": 1e-3,
        "stats_sign": 1e-3,
        "stats_verify": 1e-3,
        "stats_encrypt_u": 1e-3,
        "stats_encrypt_n": 1e-3,
        "stats_decrypt_u": 1e-3,
        "stats_decrypt_n": 1e-3,
    }

    for (name, bin_width) in names.items():
        fig = plt.figure()
        ax = fig.gca()

        labels = []
        hs = []

        hmin, hmax = float("+inf"), float("-inf")

        for (hostname, result) in sorted(results.items(), key=lambda x: x[0]):
            labels.append(hostname)

            h = getattr(result, name)

            hs.append(h)

            hmin = min(hmin, min(h))
            hmax = max(hmax, max(h))

        hmin = round_down(hmin, bin_width)
        hmax = round_up(hmax, bin_width)

        bins = np.arange(hmin, hmax, bin_width)

        ax.hist(hs, bins=bins, stacked=True, label=labels)

        if name == "stats_sha256_n":
            ax.set_xlim(0, 2e-6)

        ax.legend()
        ax.set_xlabel('Time Taken (secs)')
        ax.set_ylabel('Count')

        savefig(fig, log_dir / "graphs" / f"crypto_perf_{name}_hist.pdf")



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Crypto performance')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
