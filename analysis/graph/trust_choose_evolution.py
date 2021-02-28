#!/usr/bin/env python3

import subprocess
import math
import pathlib
from ipaddress import IPv6Address
from pprint import pprint

import numpy as np
import scipy.stats as stats

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from analysis.parser.wsn_pyterm import main as parse, MonitoringTask, RoutingTask
from analysis.graph.util import savefig

from common.names import ip_to_name, eui64_to_name

plt.rcParams['text.usetex'] = True
plt.rcParams['font.size'] = 12

capability_to_task = {
    "envmon": MonitoringTask,
    "routing": RoutingTask,
}

def main(log_dir: pathlib.Path, ax2_ymax: float):
    (log_dir / "graphs").mkdir(parents=True, exist_ok=True)

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
            (f"{hostname} eval {eui64_to_name(target)}"): [
                task.time

                for task in result.tasks
                if isinstance(task.details, capability_to_task[capability])
                if ip_to_name(task.target) == eui64_to_name(target)
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
            ax.plot(X, Y, label=f"{hostname} eval {eui64_to_name(target)}")

        ax.set_xlabel('Time')
        ax.set_ylabel('Trust Value (lines)')
        ax2.set_ylabel('Number of tasks submitted (bars)')

        ax.set_ylim(0, 1)
        ax2.set_ylim(0, ax2_ymax)

        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

        ax.legend(ncol=3, fontsize="small", loc="center", bbox_to_anchor=(0.5,1.075))

        savefig(fig, f"{log_dir}/graphs/banded_trust_value_vs_time_{capability}.pdf")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Graph Trust Value Over Time')
    parser.add_argument('--log-dir', type=pathlib.Path, default=["results"], nargs='+', help='The directory which contains the log output')
    parser.add_argument("--ax2-ymax", type=float, default=20, help="The ymax for ax2")

    args = parser.parse_args()

    for log_dir in args.log_dir:
        print(f"Graphing for {log_dir}")
        main(log_dir, args.ax2_ymax)
