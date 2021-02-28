#!/usr/bin/env python3
from __future__ import annotations

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
from analysis.graph.util import savefig

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

def packet_length(packet) -> int:
    # Count the length of the fragments, if this packet was fragmented
    if '6lowpan' in packet and hasattr(packet['6lowpan'], "reassembled_length"):
        return int(packet['6lowpan'].reassembled_length)
    else:
        return int(packet.length)

def main(log_dir: pathlib.Path, tx_ymax: Optional[float], rx_ymax: Optional[float]):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

    results = parse(log_dir, quiet=True)

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
        ("tx", tx_ymax): XYs_tx,
        ("rx", rx_ymax): XYs_rx,
    }

    bin_width = timedelta(minutes=6)

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

            savefig(fig, log_dir / "graphs" / f"{name}-by-type-{hostname}.pdf")

    # Table of the percentage of bytes in each category
    hostnames = sorted(set(XYs_tx.keys()) | set(XYs_rx.keys()))

    for hostname in hostnames:
        #print(hostname)

        log_file = log_dir / "graphs" / f"{hostname}-messages.tex"

        with open(log_file, "w") as f:
            print("\\begin{table}[t]", file=f)
            print("\\centering", file=f)
            print("\\begin{tabular}{l S[table-format=6] S[table-format=3.1] S[table-format=6] S[table-format=3.1]}", file=f)
            print("    \\toprule", file=f)
            print("    ~ & \\multicolumn{2}{c}{Tx} & \\multicolumn{2}{c}{Rx} \\\\", file=f)
            print("    Category & {(\\si{\\byte})} & {(\\%)} & {(\\si{\\byte})} & {(\\%)} \\\\", file=f)
            print("    \\midrule", file=f)

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
                print(f"{name} & {XY_tx.get(name, 0)} & {round(100*XY_tx.get(name, 0)/total_tx,1)} & {XY_rx.get(name, 0)} & {round(100*XY_rx.get(name, 0)/total_rx,1)} \\\\", file=f)
            print("\\midrule", file=f)
            print(f"Total & {total_tx} & 100 & {total_rx} & 100 \\\\", file=f)

            print("\\bottomrule", file=f)
            print("\\end{tabular}", file=f)
            print(f"\\caption{{Message tx and rx for {hostname}}}", file=f)
            #print("\\label{tab:ram-flash-usage}", file=f)
            print("\\end{table}", file=f)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Messages sent and received')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')
    parser.add_argument("--tx-ymax", type=float, default=None, help="The tx ymax")
    parser.add_argument("--rx-ymax", type=float, default=None, help="The rx ymax")

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir, args.tx_ymax, args.rx_ymax)
