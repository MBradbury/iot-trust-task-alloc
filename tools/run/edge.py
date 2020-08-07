#!/usr/bin/env python3

import argparse
import subprocess
import time
import os

from util import Teed

DEFAULT_LOG_DIR="~/iot-trust-task-alloc/logs"

parser = argparse.ArgumentParser(description='Edge runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--mote", default="/dev/ttyUSB0", help="The mote to flash.")
parser.add_argument("--mote_type", choices=["zolertia", "telosb"], default="zolertia", help="The type of mote.")
parser.add_argument("--firmware_type", choices=["contiki", "riot"], default="contiki", help="The OS that was used to create the firmware.")

parser.add_argument("--applications", nargs="+", type=str,
                    choices=["challenge_response", "monitoring", "routing"],
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

with open(flash_log_path, 'w') as flash_log:
    teed = Teed()
    p = subprocess.Popen(
        f"./flash.py '{args.mote}' edge.bin {args.mote_type} {args.firmware_type}",
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

time.sleep(1)

with open(edge_bridge_log_path, 'w') as edge_bridge:
    teed = Teed()

    edge_bridge_proc = subprocess.Popen(
        f"./edge_bridge.py",
        cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/applications"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(edge_bridge_proc, stdout=edge_bridge, stderr=edge_bridge)

    time.sleep(1)

    apps = []

    for application in args.applications:
        app_log = open(application_log_path.format(application), 'w')

        p = subprocess.Popen(
            f"./{application}.py",
            cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/applications"),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
        )
        teed.add(p, stdout=app_log, stderr=app_log)

        apps.append((p, app_log))


    teed.wait()
    for (app, f) in apps:
        app.wait()
        f.close()
    edge_bridge_proc.wait()
