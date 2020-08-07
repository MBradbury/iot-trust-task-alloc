#!/usr/bin/env python3

import argparse
import subprocess
import time
import os

from util import Teed, Popen

DEFAULT_LOG_DIR="~/iot-trust-task-alloc/logs"

parser = argparse.ArgumentParser(description='WSN runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--mote", default="/dev/ttyUSB0", help="The mote to flash.")
parser.add_argument("--mote_type", choices=["zolertia", "telosb"], default="zolertia", help="The type of mote.")
parser.add_argument("--firmware_type", choices=["contiki", "riot"], default="contiki", help="The OS that was used to create the firmware.")

args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

flash_log_path = os.path.join(args.log_dir, f"wsn.{hostname}.flash.log")
pyterm_log_path = os.path.join(args.log_dir, f"wsn.{hostname}.pyterm.log")

print(f"Logging flash to {flash_log_path}", flush=True)
print(f"Logging pyterm to {pyterm_log_path}", flush=True)

with open(flash_log_path, 'w') as flash_log:
    teed = Teed()
    flash = Popen(
        f"python3 flash.py '{args.mote}' node.bin {args.mote_type} {args.firmware_type}",
        cwd=os.path.expanduser("~/pi-client"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(flash, stdout=flash_log, stderr=flash_log)
    teed.wait()
    flash.wait()
    print("Flashing finished!", flush=True)

time.sleep(2)

with open(pyterm_log_path, 'w') as pyterm_log:
    teed = Teed()

    # stdin=subprocess.PIPE is needed in order to ensure that a stdin handle exists.
    # This is because this script may be called under nohup in which case stdin won't exist.
    pyterm = Popen(
        f"python3 pyterm -b 115200 -p {args.mote}",
        cwd=os.path.expanduser("~/pi-client/tools"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(pyterm, stdout=pyterm_log, stderr=pyterm_log)
    teed.wait()
    pyterm.wait()
    print("pyterm finished!", flush=True)
