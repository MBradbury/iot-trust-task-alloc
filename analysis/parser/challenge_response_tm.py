#!/usr/bin/env python3

import os
import glob
from datetime import datetime
import re
import ipaddress
import ast
from dataclasses import dataclass
from enum import IntEnum

from analysis.parser.common import parse_contiki

class ChallengeResponseType(IntEnum):
    NO_ACK = 0
    TIMEOUT = 1
    RESP = 2

@dataclass(frozen=True)
class ChallengeResponse:
    kind: ChallengeResponseType
    good: bool

@dataclass(frozen=True)
class EdgeResourceTM:
    epoch: int
    blacklisted: bool

@dataclass(frozen=True)
class TrustModelUpdate:
    time: datetime
    edge_id: str
    cr: ChallengeResponse
    tm_from: EdgeResourceTM
    tm_to: EdgeResourceTM

class ChallengeResponseAnalyser:
    RE_TRUST_UPDATING = re.compile(r'Updating Edge ([0-9A-Za-z]+) TM cr \(type=([0-9]),good=([01])\): EdgeResourceTM\(epoch=([0-9]+),blacklisted=([01])\) -> EdgeResourceTM\(epoch=([0-9]+),blacklisted=([01])\)')

    def __init__(self, hostname):
        self.hostname = hostname

        self.tm_updates = []

    def analyse(self, f):
        for (time, log_level, module, line) in parse_contiki(f):

            if module == "trust-comm":
                if line.startswith("Updating Edge"):
                    self._process_updating_edge(time, log_level, module, line)
                else:
                    pass

            elif module == "A-cr":
                pass

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
        m_tm_from_blacklisted = True if int(m.group(5)) == 1 else False
        m_tm_to_epoch = int(m.group(6))
        m_tm_to_blacklisted = True if int(m.group(7)) == 1 else False

        cr = ChallengeResponse(m_cr_type, m_cr_good)

        tm_from = EdgeResourceTM(m_tm_from_epoch, m_tm_from_blacklisted)
        tm_to = EdgeResourceTM(m_tm_to_epoch, m_tm_to_blacklisted)

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
