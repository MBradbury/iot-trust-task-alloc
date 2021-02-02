#!/usr/bin/env python3

import argparse
import subprocess
import time
import os
import sys

from resource_rich.monitor.monitor_impl import MonitorBase

from tools.run.util import Teed, Popen, StreamNoTimestamp

DEFAULT_LOG_DIR="~/iot-trust-task-alloc/logs"

parser = argparse.ArgumentParser(description='Edge runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--mote", default="/dev/ttyUSB0", help="The mote to flash.")
parser.add_argument("--mote_type", choices=["zolertia", "telosb"], default="zolertia", help="The type of mote.")
parser.add_argument("--firmware_type", choices=["contiki", "riot"], default="contiki", help="The OS that was used to create the firmware.")

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

parser.add_argument("--application", nargs='*', metavar='application-name nice params',
                    action=ApplicationAction,
                    help="The applications to start")

args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

motelist_log_path = os.path.join(args.log_dir, f"edge.{hostname}.motelist.log")
flash_log_path = os.path.join(args.log_dir, f"edge.{hostname}.flash.log")
edge_bridge_log_path = os.path.join(args.log_dir, f"edge.{hostname}.edge_bridge.log")
application_log_path = os.path.join(args.log_dir, f"edge.{hostname}.{{}}.log")

print(f"Logging motelist to {motelist_log_path}", flush=True)
print(f"Logging flash to {flash_log_path}", flush=True)
print(f"Logging edge_bridge to {edge_bridge_log_path}", flush=True)

with open(motelist_log_path, 'w') as motelist_log:
    teed = Teed()
    motelist = Popen(
        f"./motelist-zolertia",
        cwd=os.path.expanduser("~/pi-client/tools"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(motelist,
             stdout=[motelist_log, StreamNoTimestamp(sys.stdout)],
             stderr=[motelist_log, StreamNoTimestamp(sys.stderr)])
    teed.wait()
    motelist.wait()

time.sleep(0.1)

with open(flash_log_path, 'w') as flash_log:
    teed = Teed()
    p = Popen(
        f"python3 flash.py '{args.mote}' edge.bin {args.mote_type} {args.firmware_type}",
        cwd=os.path.expanduser("~/pi-client"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(p,
             stdout=[flash_log, StreamNoTimestamp(sys.stdout)],
             stderr=[flash_log, StreamNoTimestamp(sys.stderr)])
    teed.wait()
    p.wait()
    print("Flashing finished!", flush=True)

time.sleep(0.1)

with open(edge_bridge_log_path, 'w') as edge_bridge, \
     MonitorBase(f"edge.{hostname}", log_dir=args.log_dir) as pcap_monitor:
    teed = Teed()

    edge_bridge_proc = Popen(
        f"python3 edge_bridge.py",
        cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/applications"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(edge_bridge_proc,
             stdout=[pcap_monitor, edge_bridge, StreamNoTimestamp(sys.stdout)],
             stderr=[pcap_monitor, edge_bridge, StreamNoTimestamp(sys.stderr)])

    time.sleep(2)

    apps = []

    for (application, niceness, params) in args.application:
        app_specific_log_path = application_log_path.format(application)

        print(f"Logging application {application} to {app_specific_log_path}", flush=True)

        app_log = open(app_specific_log_path, 'w')

        p = Popen(
            f"nice -n {niceness} python3 {application}.py {params}",
            cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/applications"),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
        )
        teed.add(p,
             stdout=[app_log, StreamNoTimestamp(sys.stdout)],
             stderr=[app_log, StreamNoTimestamp(sys.stderr)])

        apps.append((p, app_log))

        # Wait a bit between applications being started
        time.sleep(2)


    teed.wait()
    for (app, f) in apps:
        app.wait()
        f.close()
    edge_bridge_proc.wait()
