#!/usr/bin/env python3

import os
import subprocess
import math
from ipaddress import IPv6Address
from pprint import pprint

import numpy as np
import scipy.stats as stats

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.wsn_pyterm import main as parse, MonitoringTask, RoutingTask
from analysis.graph.util import savefig, check_fonts

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

edge_ids_to_names = {
    "00124b0014d52bd6": "rr2",
    "00124b0014d52f05": "rr6",
}

ips_to_names = {
    IPv6Address('fd00::212:4b00:14d5:2bd6'): "rr2",
    IPv6Address('fd00::212:4b00:14d5:2f05'): "rr6",
}

capability_to_task = {
    "envmon": MonitoringTask,
    "routing": RoutingTask,
}

def main(log_dir):
    if not os.path.isdir(f"{log_dir}/graphs"):
        os.makedirs(f"{log_dir}/graphs")

    results = parse(log_dir)

    capabilities = {
        value.capability

        for result
        in results.values()

        for value
        in result.trust_choose.values
    }

    targets = {
        value.target

        for result
        in results.values()

        for value
        in result.trust_choose.values
    }

    CXYs = {
        capability: {
            (hostname, target): [
                (value.time, value.value)
                for value
                in result.trust_choose.values
                if value.target == target
                if value.capability == capability
            ]

            for (hostname, result)
            in results.items()

            for target in targets
        }

        for capability in capabilities
    }

    CHs = {
        capability: {
            (f"{hostname} eval {edge_ids_to_names[target]}"): [
                task.time

                for task in result.tasks
                if isinstance(task.details, capability_to_task[capability])
                if ips_to_names[task.target] == edge_ids_to_names[target]
            ]

            for (hostname, result)
            in results.items()

            for target in targets
        }

        for capability in capabilities
    }

    # TODO: Draw some bar graphs of which nodes tasks were submitted to

    for (capability, XYs) in CXYs.items():
        fig = plt.figure()
        ax = fig.gca()


        Hs = CHs[capability]

        print(capability)
        pprint(Hs)

        labels, hs = zip(*list(sorted(Hs.items(), key=lambda x: x[0])))

        ax2 = ax.twinx()
        ax2.hist(hs, bins=None, histtype='bar', label=labels, rwidth=0.6)



        for (label, XY) in sorted(XYs.items(), key=lambda x: x[0]):
            hostname, target = label

            X, Y = zip(*XY)
            ax.plot(X, Y, label=f"{hostname} eval {edge_ids_to_names[target]}")

        ax.set_xlabel('Time')
        ax.set_ylabel('Trust Value (lines)')
        ax2.set_ylabel('Number of tasks submitted (bars)')

        ax.set_ylim(0, 1)
        ax2.set_ylim(0, 6)

        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

        ax.legend(ncol=3, fontsize="small", loc="center", bbox_to_anchor=(0.5,1.075))

        target = f"{log_dir}/graphs/banded_trust_value_vs_time_{capability}.pdf"
        fig.savefig(target, bbox_inches='tight')
        #subprocess.run(f"pdfcrop {target} {target}", shell=True)
        print("Produced:", target)
        check_fonts(target)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Trust Value Over Time')
    parser.add_argument('--log-dir', type=str, default=["results"], nargs='+', help='The directory which contains the log output')

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir)
