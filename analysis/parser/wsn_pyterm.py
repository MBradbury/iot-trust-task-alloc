#!/usr/bin/env python3

import os
import glob
from datetime import datetime
import re
import ipaddress
import ast
from dataclasses import dataclass
from enum import IntEnum
from typing import Union

from analysis.parser.common import parse_contiki

class ChallengeResponseType(IntEnum):
    NO_ACK = 0
    TIMEOUT = 1
    RESPONSE = 2

@dataclass(frozen=True)
class ChallengeResponse:
    kind: ChallengeResponseType
    good: bool

@dataclass(frozen=True)
class EdgeResourceTM:
    epoch: int
    bad: bool

@dataclass(frozen=True)
class TrustModelUpdate:
    time: datetime
    edge_id: str
    cr: ChallengeResponse
    tm_from: EdgeResourceTM
    tm_to: EdgeResourceTM


@dataclass(frozen=True)
class Coordinate:
    latitude: float
    longitude: float

@dataclass(frozen=True)
class MonitoringTask:
    length: int

@dataclass(frozen=True)
class RoutingTask:
    length: int
    source: Coordinate
    destination: Coordinate

@dataclass(frozen=True)
class Task:
    target: ipaddress.IPv6Address
    time: datetime
    details: Union[MonitoringTask, RoutingTask]

class ChallengeResponseAnalyser:
    RE_TRUST_UPDATING = re.compile(r'Updating Edge ([0-9A-Za-z]+) TM cr \(type=([0-9]),good=([01])\): EdgeResourceTM\(epoch=([0-9]+),(blacklisted|bad)=([01])\) -> EdgeResourceTM\(epoch=([0-9]+),(blacklisted|bad)=([01])\)')

    RE_ROUTING_GENERATED = re.compile(r'Generated message \(len=([0-9]+)\) for path from \(([0-9.-]+),([0-9.-]+)\) to \(([0-9.-]+),([0-9.-]+)\)')
    RE_MONITORING_GENERATED = re.compile(r'Generated message \(len=([0-9]+)\)')

    RE_TASK_SENT = re.compile(r'Message sent to coap://\[(.+)\]:5683')

    def __init__(self, hostname):
        self.hostname = hostname

        self.tm_updates = []

        self.tasks = []
        self._pending_tasks = {}

    def analyse(self, f):
        for (time, log_level, module, line) in parse_contiki(f):

            if module == "trust-comm":
                if line.startswith("Updating Edge"):
                    self._process_updating_edge(time, log_level, module, line)
                else:
                    pass

            elif module == "A-cr":
                pass

            elif module == "A-routing":
                if line.startswith("Generated message"):
                    m = self.RE_ROUTING_GENERATED.match(line)
                    m_len = int(m.group(1))
                    m_source_lat = float(m.group(2))
                    m_source_lon = float(m.group(3))
                    m_dest_lat = float(m.group(4))
                    m_dest_lon = float(m.group(5))

                    source = Coordinate(m_source_lat, m_source_lon)
                    destination = Coordinate(m_dest_lat, m_dest_lon)

                    self._pending_tasks[module] = RoutingTask(m_len, source, destination)

                elif line.startswith("Message sent to"):
                    task_details = self._pending_tasks[module]
                    del self._pending_tasks[module]

                    m = self.RE_TASK_SENT.match(line)
                    m_target = ipaddress.ip_address(m.group(1))

                    t = Task(m_target, time, task_details)
                    self.tasks.append(t)

            elif module == "A-envmon":
                if line.startswith("Generated message"):
                    m = self.RE_MONITORING_GENERATED.match(line)
                    m_len = int(m.group(1))

                    self._pending_tasks[module] = MonitoringTask(m_len)

                elif line.startswith("Message sent to"):
                    task_details = self._pending_tasks[module]
                    del self._pending_tasks[module]

                    m = self.RE_TASK_SENT.match(line)
                    m_target = ipaddress.ip_address(m.group(1))

                    t = Task(m_target, time, task_details)
                    self.tasks.append(t)

            #if module not in ("A-cr", "trust-comm"):
            #    continue

            #print((time, module, line))

    def _process_updating_edge(self, time, log_level, module, line):
        m = self.RE_TRUST_UPDATING.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_edge_id = m.group(1)
        m_cr_type = ChallengeResponseType(int(m.group(2)))
        m_cr_good = True if int(m.group(3)) == 1 else False
        m_tm_from_epoch = int(m.group(4))
        m_tm_from_bad = True if int(m.group(5)) == 1 else False
        m_tm_to_epoch = int(m.group(6))
        m_tm_to_bad = True if int(m.group(7)) == 1 else False

        cr = ChallengeResponse(m_cr_type, m_cr_good)

        tm_from = EdgeResourceTM(m_tm_from_epoch, m_tm_from_bad)
        tm_to = EdgeResourceTM(m_tm_to_epoch, m_tm_to_bad)

        u = TrustModelUpdate(time, m_edge_id, cr, tm_from, tm_to)

        self.tm_updates.append(u)


def main(log_dir):
    print(f"Looking for results in {log_dir}")

    gs = glob.glob(f"{log_dir}/*.pyterm.log")

    results = {}

    for g in gs:
        print(f"Processing {g}...")
        bg = os.path.basename(g)

        kind, hostname, cr, log = bg.split(".", 3)

        if kind != "wsn":
            print("Can only have challenge_response results from an wsn node")
            continue

        a = ChallengeResponseAnalyser(hostname)

        with open(g, 'r') as f:
            a.analyse(f)

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Challenge Response')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
