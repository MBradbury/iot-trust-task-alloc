#!/usr/bin/env python3

import os
import glob
from datetime import datetime
import re
import ipaddress
import ast
from dataclasses import dataclass
import pathlib

@dataclass(frozen=True)
class Challenge:
    source: ipaddress.IPv6Address
    difficulty: int
    data: bytes

@dataclass(frozen=True)
class Response:
    max_duration: int
    duration: float
    iterations: int
    prefix: bytes

@dataclass(frozen=True)
class ChallengeResponse:
    challenge_time: datetime
    response_time: datetime

    challenge: Challenge
    response: Response

class ChallengeResponseAnalyser:
    RE_RECEIVE_CHALLENGE = re.compile(r"Received challenge at (.+) from (.+) <difficulty=([0-9]+), data=(b[\"'].+[\"'])>")
    RE_CHALLENGE_RESPONSE = re.compile(r"Job \(IPv6Address\('(.+)'\), ([0-9]+), (b[\"'].+[\"']), ([0-9]+)\) took ([0-9\.]+) seconds and ([0-9]+) iterations and found prefix (b[\"'].+[\"'])")
    RE_BECOMING = re.compile(r"Becoming (good|bad)")
    RE_CURRENTLY = re.compile(r"Currently (good|bad), so behaving (correctly|incorrectly with ([A-Za-z-]+))")

    def __init__(self, hostname: str):
        self.hostname = hostname

        self.start_times = []
        self.challenges = []
        self.challenge_responses = []

        # For bad_challenge_response, there will be times at which the system misbehaves
        self.behaviour_changes = []
        self.task_actions = []

    def analyse(self, f):
        for line in f:
            try:
                time, rest = line.strip().split(" # ", 1)

                time = datetime.fromisoformat(time)

                level, app, rest = rest.split(":", 2)

                if rest.startswith("Starting"):
                    self._process_starting(time, level, app, rest)
                elif rest.startswith("Received challenge"):
                    self._process_received_challenge(time, level, app, rest)
                elif rest.startswith("Job"):
                    self._process_job_complete(time, level, app, rest)
                elif rest.startswith("Writing"):
                    self._process_writing(time, level, app, rest)
                elif rest.startswith("Becoming"):
                    self._process_becoming(time, level, app, rest)
                elif rest.startswith("Currently"):
                    self._process_currently(time, level, app, rest)
                else:
                    print(f"Unknown line contents {rest} at {time}")
            except ValueError as ex:
                print(ex)
                print(time, line)
                break

    def _process_starting(self, time: datetime, level: str, app: str, line: str):
        self.start_times.append(time)

    def _process_received_challenge(self, time: datetime, level: str, app: str, line: str):
        m = self.RE_RECEIVE_CHALLENGE.match(line)
        #m_time = datetime.fromisoformat(m.group(1))
        m_source = ipaddress.ip_address(m.group(2))
        m_difficulty = int(m.group(3))
        m_data = ast.literal_eval(m.group(4))

        c = Challenge(m_source, m_difficulty, m_data)

        self.challenges.append((time, c))

    def _process_job_complete(self, time: datetime, level: str, app: str, line: str):
        m = self.RE_CHALLENGE_RESPONSE.match(line)
        m_from = ipaddress.ip_address(m.group(1))
        m_difficulty = int(m.group(2))
        m_data = ast.literal_eval(m.group(3))

        m_max_duration = int(m.group(4))
        m_duration = float(m.group(5))
        m_iterations = int(m.group(6))
        m_prefix = ast.literal_eval(m.group(7))

        c = Challenge(m_from, m_difficulty, m_data)
        r = Response(m_max_duration, m_duration, m_iterations, m_prefix)

        for (ct, cx) in self.challenges:
            if cx == c:
                break
        else:
            raise RuntimeError(f"Failed to find a challenge {c} in {self.challenges}")

        cr = ChallengeResponse(ct, time, c, r)

        self.challenge_responses.append(cr)

    def _process_writing(self, time: datetime, level: str, app: str, line: str):
        pass

    def _process_becoming(self, time: datetime, level: str, app: str, line: str):
        """When changing from behaving well or not"""
        m = self.RE_BECOMING.match(line)
        m_behaviour = m.group(1) == "good"

        self.behaviour_changes.append((time, m_behaviour))

    def _process_currently(self, time: datetime, level: str, app: str, line: str):
        """How the application misbehaves"""
        m = self.RE_CURRENTLY.match(line)
        m_behaviour = m.group(1) == "good"
        m_action = m.group(2) == "correctly"
        m_action_type = m.group(3)

        self.task_actions.append((time, m_behaviour, m_action, m_action_type))

def main(log_dir: pathlib.Path):
    print(f"Looking for results in {log_dir}")

    gs = log_dir.glob("*challenge_response.log")

    results = {}

    for g in gs:
        print(f"Processing {g}...")
        bg = os.path.basename(g)

        kind, hostname, cr, log = bg.split(".", 3)

        if kind != "edge":
            print("Can only have challenge_response results from an edge node")
            continue

        a = ChallengeResponseAnalyser(hostname)

        with open(g, 'r') as f:
            a.analyse(f)

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Challenge Response')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
