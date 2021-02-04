#!/usr/bin/env python3

import os
from datetime import datetime
import re
from dataclasses import dataclass
import pathlib

import numpy as np
import scipy.stats as stats

from analysis.parser.common import parse_contiki

@dataclass(frozen=True)
class LengthStats:
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
    
    RE_ENCRYPT = re.compile(r'encrypt\(([0-9]+)\), ([0-9]+) us')
    RE_DECRYPT = re.compile(r'decrypt\(([0-9]+)\), ([0-9]+) us')

    def __init__(self, hostname: str):
        self.hostname = hostname

        self.stats_sha256 = []
        self.stats_ecdh = []
        self.stats_sign = []
        self.stats_verify = []
        self.stats_encrypt = []
        self.stats_decrypt = []

        self.res = {
            self.RE_SHA256_END: self._process_sha256_end,
            self.RE_ECDH: self._process_ecdh,
            self.RE_SIGN: self._process_sign,
            self.RE_VERIFY: self._process_verify,
            self.RE_ENCRYPT: self._process_encrypt,
            self.RE_DECRYPT: self._process_decrypt,
        }

    def analyse(self, f):
        for (time, log_level, module, line) in parse_contiki(f):

            if module in ("crypto-sup", "profile"):
                for (r, f) in self.res.items():
                    m = r.match(line)
                    if m is not None and f is not None:
                        f(time, log_level, module, line, m)
                        break

    def summary(self):
        if self.stats_ecdh:
            print("ECDH", stats.describe(self.stats_ecdh))

        if self.stats_sign:
            print("Sign", stats.describe(self.stats_sign))

        if self.stats_verify:
            print("Verify", stats.describe(self.stats_verify))

        if self.stats_sha256:
            self.stats_sha256_u = [x.seconds for x in self.stats_sha256]
            self.stats_sha256_n = [x.seconds / x.length for x in self.stats_sha256]
            
            print("SHA256 (u)", stats.describe(self.stats_sha256_u))
            print("SHA256 (n)", stats.describe(self.stats_sha256_n))

        if self.stats_encrypt:
            self.stats_encrypt_u = [x.seconds for x in self.stats_encrypt]
            self.stats_encrypt_n = [x.seconds / x.length for x in self.stats_encrypt]
            
            print("encrypt (u)", stats.describe(self.stats_encrypt_u))
            print("encrypt (n)", stats.describe(self.stats_encrypt_n))

        if self.stats_decrypt:
            self.stats_decrypt_u = [x.seconds for x in self.stats_decrypt]
            self.stats_decrypt_n = [x.seconds / x.length for x in self.stats_decrypt]
            
            print("decrypt (u)", stats.describe(self.stats_decrypt_u))
            print("decrypt (n)", stats.describe(self.stats_decrypt_n))

    def _process_sha256_end(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_len = int(m.group(1))
        m_s = us_to_s(int(m.group(2)))

        self.stats_sha256.append(LengthStats(m_len, m_s))

    def _process_ecdh(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_s = us_to_s(int(m.group(1)))

        self.stats_ecdh.append(m_s)

    def _process_sign(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_s = us_to_s(int(m.group(1)))

        self.stats_sign.append(m_s)

    def _process_verify(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_s = us_to_s(int(m.group(1)))

        self.stats_verify.append(m_s)

    def _process_encrypt(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_len = int(m.group(1))
        m_s = us_to_s(int(m.group(2)))

        self.stats_encrypt.append(LengthStats(m_len, m_s))

    def _process_decrypt(self, time: datetime, log_level: str, module: str, line: str, m: str):
        m_len = int(m.group(1))
        m_s = us_to_s(int(m.group(2)))

        self.stats_decrypt.append(LengthStats(m_len, m_s))

def print_mean_ci(name: str, x: np.array, confidence: float=0.95):
    mean, sem, n = np.mean(x), stats.sem(x), len(x)
    ci = mean - stats.t.interval(0.95, len(x)-1, loc=np.mean(x), scale=stats.sem(x))[0]

    vs = {
        "seconds": 1,
        "ms": 1e3,
        "us": 1e6,
        "ns": 1e9,
    }

    for (n, f) in vs.items():
        print(name, mean * f, ci * f, n)

def global_summary(results: Dict[str, ProfileAnalyser]):
    names = [
        "stats_sha256_u",
        "stats_sha256_n",
        "stats_ecdh",
        "stats_sign",
        "stats_verify",
        "stats_encrypt_u",
        "stats_encrypt_n",
        "stats_decrypt_u",
        "stats_decrypt_n",
    ]

    print("Global:")

    for name in names:
        print(name)

        combined = np.concatenate([getattr(x, name, []) for x in results.values()])

        if combined.size != 0:
            print(name, stats.describe(combined))
            print_mean_ci(name, combined)


def main(log_dir: pathlib.Path):
    print(f"Looking for results in {log_dir}")

    gs = log_dir.glob("profile.*.pyterm.log")

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

    global_summary(results)

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Profile pyterm')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
