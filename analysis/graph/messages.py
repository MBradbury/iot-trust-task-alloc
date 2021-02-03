#!/usr/bin/env python3

import os
import subprocess
import math
import pathlib
from ipaddress import IPv6Address
from pprint import pprint
from datetime import datetime, timedelta

import numpy as np
import scipy.stats as stats

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.pyshark_pcap import main as parse
from analysis.graph.util import savefig, check_fonts

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

hostname_to_names = {
    "wsn2": "rr2",
    "wsn3": "wsn3",
    "wsn4": "wsn4",
    "wsn5": "wsn5",
    "wsn6": "rr6",
}

def round_down(x, a):
    return math.floor(x / a) * a

def round_up(x, a):
    return math.ceil(x / a) * a

def packet_length(packet):
    # Count the length of the fragments, if this packet was fragmented
    if '6lowpan' in packet and hasattr(packet['6lowpan'], "reassembled_length"):
        return int(packet['6lowpan'].reassembled_length)
    else:
        return int(packet.length)

def main(log_dir: pathlib.Path):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse(log_dir)

    XYs_tx = {
        hostname: [
            (name, [datetime.fromtimestamp(float(value.sniff_timestamp)) for value in values], [packet_length(value) for value in values])
            for (name, values)
            in result.tx.items()
        ]

        for (hostname, result)
        in results.items()
    }

    XYs_rx = {
        hostname: [
            (name, [datetime.fromtimestamp(float(value.sniff_timestamp)) for value in values], [packet_length(value) for value in values])
            for (name, values)
            in result.rx.items()
        ]

        for (hostname, result)
        in results.items()
    }

    to_graph = {
        ("tx", 75_000): XYs_tx,
        ("rx", 30_000): XYs_rx,
    }

    bin_width = timedelta(minutes=5)

    min_time = min(r.min_snift_time for r in results.values())
    max_time = min(r.max_snift_time for r in results.values())

    min_time = datetime.fromtimestamp(min_time)
    max_time = datetime.fromtimestamp(max_time)

    bins = [min_time]
    while bins[-1] + bin_width < max_time:
        bins.append(bins[-1] + bin_width)
    bins.append(max_time)


    # Make the colors the same between rx and tx graphs
    kinds1 = {name for nvs in XYs_tx.values() for (name, times, lengths) in nvs}
    kinds2 = {name for nvs in XYs_rx.values() for (name, times, lengths) in nvs}

    kinds = kinds1 | kinds2

    ckind = {
        kind: plt.cm.get_cmap('tab20')(i)
        for i, kind in enumerate(sorted(kinds))
    }

    for ((name, ymax), XYs) in to_graph.items():

        for (hostname, metric_values) in XYs.items():

            fig = plt.figure()
            ax = fig.gca()

            labels, values, weights = zip(*sorted(metric_values, key=lambda x: x[0]))

            colors = [ckind[label] for label in labels]

            ax.hist(values, bins=bins, histtype='bar', stacked=True, label=labels, weights=weights, color=colors, rwidth=1)

            ax.set_xlabel('Time')
            ax.set_ylabel(f'Message Length (bytes) {"Sent" if name == "tx" else "Received"} During Window')

            ax.set_ylim(0, ymax)

            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

            ax.legend(ncol=3, loc="center", fontsize="small", bbox_to_anchor=(0.5,1.125))

            target = log_dir / "graphs" / f"{name}-by-type-{hostname}.pdf"
            fig.savefig(str(target), bbox_inches='tight')
            #subprocess.run(f"pdfcrop {target} {target}", shell=True)
            print("Produced:", target)
            check_fonts(target)

    # TODO: Draw some bar graphs of which nodes tasks were submitted to

    # Table of the percentage of bytes in each category
    hostnames = sorted(set(XYs_tx.keys()) | set(XYs_rx.keys()))

    for hostname in hostnames:
        #print(hostname)

        print("\\begin{table}[t]")
        print("\\centering")
        print("\\begin{tabular}{l S[table-format=6] S[table-format=3.1] S[table-format=6] S[table-format=3.1]}")
        print("    \\toprule")
        print("    ~ & \\multicolumn{2}{c}{Tx} & \\multicolumn{2}{c}{Rx} \\\\")
        print("    Category & {(\\si{\\byte})} & {(\\%)} & {(\\si{\\byte})} & {(\\%)} \\\\")
        print("    \\midrule")

        XY_tx = XYs_tx.get(hostname, [])
        XY_rx = XYs_rx.get(hostname, [])

        XY_tx = {
            name: sum(lengths)
            for (name, dates, lengths) in XY_tx
        }
        total_tx = sum(XY_tx.values())

        XY_rx = {
            name: sum(lengths)
            for (name, dates, lengths) in XY_rx
        }
        total_rx = sum(XY_rx.values())

        names = sorted(set(XY_tx.keys()) | set(XY_rx.keys()))

        for name in names:
            print(f"{name} & {XY_tx.get(name, 0)} & {round(100*XY_tx.get(name, 0)/total_tx,1)} & {XY_rx.get(name, 0)} & {round(100*XY_rx.get(name, 0)/total_rx,1)} \\\\")
        print("\\midrule")
        print(f"Total & {total_tx} & 100 & {total_rx} & 100 \\\\")

        print("\\bottomrule")
        print("\\end{tabular}")
        print(f"\\caption{{Message tx and rx for {hostname}}}")
        #print("\\label{tab:ram-flash-usage}")
        print("\\end{table}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Messages sent and received')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
