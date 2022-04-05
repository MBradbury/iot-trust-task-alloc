#!/usr/bin/env python3

import os
import glob
import datetime
import re
import ipaddress
import ast
from dataclasses import dataclass
import pathlib

from analysis.parser.edge import EdgeAnalyser, Task

@dataclass(frozen=True)
class Response:
    task: Task
    duration: float
    status: str
    route_length: int

class RoutingAnalyser(EdgeAnalyser):
    RE_JOB_RESPONSE = re.compile(
        r"Job \(IPv6Address\('(.+)'\), (datetime\.datetime\(.+\)), (.+)\) took ([0-9\.]+) seconds with status (success|no_route|gave_up) route length = ([0-9]+)")

    def __init__(self, hostname: str):
        super().__init__(hostname)

        self.task_completed = []

    def analyse_line(self, time, level, app, rest):
        if rest.startswith("Job"):
            self._process_job_complete(time, level, app, rest)
        elif rest.startswith("Writing"):
            self._process_writing(time, level, app, rest)
        else:
            super().analyse_line(time, level, app, rest)

    def _process_job_complete(self, time: datetime.datetime, level: str, app: str, line: str):
        m = self.RE_JOB_RESPONSE.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_from = ipaddress.ip_address(m.group(1))
        m_dt = eval(m.group(2))
        m_data = ast.literal_eval(m.group(3))

        m_duration = float(m.group(4))
        m_status = m.group(5)
        m_route_length = int(m.group(6))

        t = Task(m_dt, m_from, m_data)
        r = Response(t, m_duration, m_status, m_route_length)

        self.task_completed.append(r)

    def _process_writing(self, time: datetime.datetime, level: str, app: str, line: str):
        pass


def main(log_dir: pathlib.Path):
    print(f"Looking for results in {log_dir}")

    gs = log_dir.glob("*routing.log")

    results = {}

    for g in gs:
        print(f"Processing {g}...")
        bg = os.path.basename(g)

        kind, hostname, cr, log = bg.split(".", 3)

        if kind != "edge":
            print("Can only have routing results from an edge node")
            continue

        a = RoutingAnalyser(hostname)

        with open(g, 'r') as f:
            a.analyse(f)

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Routing Response')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
