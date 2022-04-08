#!/usr/bin/env python3

import argparse
import subprocess
import time
import sys
from pathlib import Path
import shlex

from resource_rich.monitor.monitor_impl import MonitorBase

from tools.run import supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import Teed, Popen, StreamNoTimestamp, ApplicationRunner
from tools.keygen.util import eui64_to_ipv6

class EdgeRunner(ApplicationRunner):
    log_name = "edge"
    binary_name = "edge.bin"

    def __init__(self, log_dir: Path, firmware_type: str, application):
        super().__init__(log_dir, firmware_type)
        self.application = application

    def set_log_paths(self):
        super().set_log_paths()

        self.edge_bridge_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.edge_bridge.log"

    def get_application_log_path(self, application: str) -> Path:
        return self.log_dir / f"{self.log_name}.{self.hostname}.{application}.log"

    def run_edge_bridge(self):
        with open(self.edge_bridge_log_path, 'w') as edge_bridge, \
         MonitorBase(f"{self.log_name}.{self.hostname}", log_dir=self.log_dir) as pcap_monitor:
            teed = Teed()

            edge_bridge_proc = Popen(
                shlex.split(f"python3 resource_rich/applications/edge_bridge.py {self.device.identifier} {self.device.kind.value}"),
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            self.record_pid(edge_bridge_proc.pid)
            teed.add(edge_bridge_proc,
                     stdout=[pcap_monitor, edge_bridge, StreamNoTimestamp(sys.stdout)],
                     stderr=[pcap_monitor, edge_bridge, StreamNoTimestamp(sys.stderr)])

            print("Waiting for edge bridge to start before running applications...", flush=True)
            time.sleep(15)

            apps = []

            print("Running applications", flush=True)

            for (application, niceness, params) in self.application:
                app_specific_log_path = self.get_application_log_path(application)

                print(f"Logging application {application} to {app_specific_log_path}", flush=True)

                app_log = open(app_specific_log_path, 'w')

                p = Popen(
                    shlex.split(f"nice -n {niceness} python3 {application}.py {params}"),
                    cwd="resource_rich/applications",
                    #shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    encoding="utf-8",
                )
                self.record_pid(p.pid)
                teed.add(p,
                     stdout=[app_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[app_log, StreamNoTimestamp(sys.stderr)])

                apps.append((p, app_log))

                # Wait a bit between applications being started
                time.sleep(5)


            teed.wait()
            for (app, f) in apps:
                app.wait()
                f.close()
            edge_bridge_proc.wait()

    def run(self):
        print(f"CWD: {Path.cwd()}", flush=True)
        print(f"Logging motelist to {self.motelist_log_path}", flush=True)
        print(f"Logging flash to {self.flash_log_path}", flush=True)
        print(f"Logging edge bridge to {self.edge_bridge_log_path}", flush=True)

        self.run_motelist()

        time.sleep(0.1)

        device_firmware_dir = str(eui64_to_ipv6(self.device.eui64)).replace(":", "_")
        firmware_path = f"{device_firmware_dir}/{self.binary_name}"

        self.run_flash(firmware_path)

        time.sleep(0.1)

        self.run_edge_bridge()

# From: https://stackoverflow.com/questions/8526675/python-argparse-optional-append-argument-with-choices
class ApplicationAction(argparse.Action):
    CHOICES = ["challenge_response", "monitoring", "routing", "bad_challenge_response", "bad_routing"]
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            value = values[0]

            if value not in self.CHOICES:
                message = f"invalid choice: {value!r} (choose from {', '.join(self.CHOICES)})"
                raise argparse.ArgumentError(self, message)

            # If no niceness is provided, supply the default of 0
            if len(values) == 1:
                values.append(0)

            # If no arguments are provided, supply a default of no arguments
            if len(values) == 2:
                values.append("")

            if len(values) > 3:
                raise argparse.ArgumentError(self, f"too many application arguments {values}")

            # Make sure the niceness is an int and in a valid range
            values[1] = int(values[1])
            if values[1] < -20 or values[1] > 19:
                raise argparse.ArgumentError(self, f"invalid nice value {values[1]} not in range [-20, 19]")

            attr = getattr(namespace, self.dest)
            if attr is None:
                setattr(namespace, self.dest, [values])
            else:
                setattr(namespace, self.dest, attr + [values])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Edge runner')
    parser.add_argument('--log-dir', type=Path, default=DEFAULT_LOG_DIR, help='The directory to store log output')
    parser.add_argument("--firmware-type",
                        choices=supported_firmware_types,
                        default=supported_firmware_types[0],
                        help="The OS that was used to create the firmware.")

    parser.add_argument("--application", nargs='*', metavar='application-name nice params',
                        action=ApplicationAction,
                        help="The applications to start")

    args = parser.parse_args()

    runner = EdgeRunner(args.log_dir, args.firmware_type, args.application)
    runner.run()
