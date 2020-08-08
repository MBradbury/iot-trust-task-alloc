#!/usr/bin/env python3

import argparse
import subprocess
import time
import os

from util import Teed, Popen

DEFAULT_LOG_DIR="~/iot-trust-task-alloc/logs"

parser = argparse.ArgumentParser(description='Edge runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--mote", default="/dev/ttyUSB0", help="The mote to flash.")
parser.add_argument("--mote_type", choices=["zolertia", "telosb"], default="zolertia", help="The type of mote.")
parser.add_argument("--firmware_type", choices=["contiki", "riot"], default="contiki", help="The OS that was used to create the firmware.")

# From: https://stackoverflow.com/questions/8526675/python-argparse-optional-append-argument-with-choices
class ApplicationAction(argparse.Action):
    CHOICES = ["challenge_response", "monitoring", "routing", "bad_challenge_response"]
    def __call__(self, parser, namespace, values, option_string=None):
        if values:
            value = values[0]

            if value not in self.CHOICES:
                message = f"invalid choice: {value!r} (choose from {', '.join(self.CHOICES)})"
                raise argparse.ArgumentError(self, message)

            if len(values) == 1:
                values.append("")

            if len(values) > 2:
                raise argparse.ArgumentError(self, f"too many application arguments {values}")

            attr = getattr(namespace, self.dest)
            if attr is None:
                setattr(namespace, self.dest, [values])
            else:
                setattr(namespace, self.dest, attr + [values])

parser.add_argument("--application", nargs='*', metavar=('application-name', 'application-params'),
                    action=ApplicationAction,
                    help="The applications to start")

args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

flash_log_path = os.path.join(args.log_dir, f"edge.{hostname}.flash.log")
edge_bridge_log_path = os.path.join(args.log_dir, f"edge.{hostname}.edge_bridge.log")
application_log_path = os.path.join(args.log_dir, f"edge.{hostname}.{{}}.log")

print(f"Logging flash to {flash_log_path}", flush=True)
print(f"Logging edge_bridge to {edge_bridge_log_path}", flush=True)

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
    teed.add(p, stdout=flash_log, stderr=flash_log)
    teed.wait()
    p.wait()
    print("Flashing finished!", flush=True)

time.sleep(0.1)

with open(edge_bridge_log_path, 'w') as edge_bridge:
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
    teed.add(edge_bridge_proc, stdout=edge_bridge, stderr=edge_bridge)

    time.sleep(2)

    apps = []

    for (application, params) in args.application:
        app_specific_log_path = application_log_path.format(application)

        print(f"Logging application {application} to {app_specific_log_path}", flush=True)

        app_log = open(app_specific_log_path, 'w')

        p = Popen(
            f"./{application}.py {params}",
            cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/applications"),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
        )
        teed.add(p, stdout=app_log, stderr=app_log)

        apps.append((p, app_log))

        # Wait a bit between applications being started
        time.sleep(2)


    teed.wait()
    for (app, f) in apps:
        app.wait()
        f.close()
    edge_bridge_proc.wait()
