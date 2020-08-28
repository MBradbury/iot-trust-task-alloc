#!/usr/bin/env python3

import os
import glob
from datetime import datetime
import re
from dataclasses import dataclass

from scipy.stats import describe

from analysis.parser.common import parse_contiki

@dataclass(frozen=True)
class SHA256Stats:
    length: int
    seconds: float

def us_to_s(us: int) -> float:
    return us / 1000000.0

class ProfileAnalyser:
    #RE_SHA256_START = re.compile(r'Starting sha256\(([0-9]+)\)\.\.\.')
    RE_SHA256_END = re.compile(r'sha256\(([0-9]+)\), ([0-9]+) us')

    RE_ECDH = re.compile(r'ecdh2\(\), ([0-9]+) us')

    RE_SIGN = re.compile(r'ecc_dsa_sign\(\), ([0-9]+) us')
    RE_VERIFY = re.compile(r'ecc_dsa_verify\(\), ([0-9]+) us')
    

    def __init__(self, hostname):
        self.hostname = hostname

        self.stats_sha256 = []
        self.stats_ecdh = []
        self.stats_sign = []
        self.stats_verify = []

        self.res = {
            self.RE_SHA256_END: self._process_sha256_end,
            self.RE_ECDH: self._process_ecdh,
            self.RE_SIGN: self._process_sign,
            self.RE_VERIFY: self._process_verify,
        }

    def analyse(self, f):
        for (time, log_level, module, line) in parse_contiki(f):

            if module == "crypto-sup":
                for (r, f) in self.res.items():
                    m = r.match(line)
                    if m is not None and f is not None:
                        f(time, log_level, module, line, m)
                        break


            #print((time, module, line))

    def summary(self):
        print("ECDH", describe(self.stats_ecdh))
        print("Sign", describe(self.stats_sign))
        print("Verify", describe(self.stats_verify))

        print("SHA256 (u)", describe([x.seconds for x in self.stats_sha256]))
        print("SHA256 (n)", describe([x.seconds / x.length for x in self.stats_sha256]))

    def _process_sha256_end(self, time, log_level, module, line, m):
        m_len = int(m.group(1))
        m_s = us_to_s(int(m.group(2)))

        self.stats_sha256.append(SHA256Stats(m_len, m_s))

    def _process_ecdh(self, time, log_level, module, line, m):
        m_s = us_to_s(int(m.group(1)))

        self.stats_ecdh.append(m_s)

    def _process_sign(self, time, log_level, module, line, m):
        m_s = us_to_s(int(m.group(1)))

        self.stats_sign.append(m_s)

    def _process_verify(self, time, log_level, module, line, m):
        m_s = us_to_s(int(m.group(1)))

        self.stats_verify.append(m_s)

def main(log_dir):
    print(f"Looking for results in {log_dir}")

    gs = glob.glob(f"{log_dir}/profile.*.pyterm.log")

    results = {}

    for g in gs:
        print(f"Processing {g}...")
        bg = os.path.basename(g)

        kind, hostname, cr, log = bg.split(".", 3)

        if kind != "profile":
            print(f"Can only have challenge_response results from a profile node instead of {kind}")
            continue

        a = ProfileAnalyser(hostname)

        with open(g, 'r') as f:
            a.analyse(f)

        a.summary()

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Profile pyterm')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
