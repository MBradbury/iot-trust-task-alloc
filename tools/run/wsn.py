#!/usr/bin/env python3

import argparse
import subprocess
import time
import os
import sys
import pathlib

from resource_rich.monitor.monitor_impl import MonitorBase

from tools.run import supported_mote_types, supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import Teed, Popen, StreamNoTimestamp

parser = argparse.ArgumentParser(description='WSN runner')
parser.add_argument("firmware_path", metavar="firmware-path",
                    type=pathlib.Path,
                    help="The path to the firmware to deploy")

parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--mote",
                    required=True,
                    help="The mote to flash.")
parser.add_argument("--mote-type",
                    choices=supported_mote_types,
                    required=True,
                    help="The type of mote.")
parser.add_argument("--firmware-type",
                    choices=supported_firmware_types,
                    default=supported_firmware_types[0],
                    help="The OS that was used to create the firmware.")

args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

motelist_log_path = os.path.join(args.log_dir, f"wsn.{hostname}.motelist.log")
flash_log_path = os.path.join(args.log_dir, f"wsn.{hostname}.flash.log")
pyterm_log_path = os.path.join(args.log_dir, f"wsn.{hostname}.pyterm.log")

print(f"CWD: {os.getcwd()}", flush=True)
print(f"Logging motelist to {motelist_log_path}", flush=True)
print(f"Logging flash to {flash_log_path}", flush=True)
print(f"Logging pyterm to {pyterm_log_path}", flush=True)

with open(motelist_log_path, 'w') as motelist_log:
    teed = Teed()
    motelist = Popen(
        f"python3 tools/deploy/motelist.py --mote-type {args.mote_type}",
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

firmware_path = pathlib.Path.cwd() / args.firmware_path / 'node.bin'

with open(flash_log_path, 'w') as flash_log:
    teed = Teed()
    flash = Popen(
        f"python3 flash.py '{args.mote}' '{firmware_path}' {args.mote_type} {args.firmware_type}",
        cwd="tools/deploy",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(flash,
             stdout=[flash_log, StreamNoTimestamp(sys.stdout)],
             stderr=[flash_log, StreamNoTimestamp(sys.stderr)])
    teed.wait()
    flash.wait()
    print("Flashing finished!", flush=True)

time.sleep(0.1)

with open(pyterm_log_path, 'w') as pyterm_log, \
     MonitorBase(f"wsn.{hostname}", log_dir=args.log_dir) as pcap_monitor:
    teed = Teed()

    # stdin=subprocess.PIPE is needed in order to ensure that a stdin handle exists.
    # This is because this script may be called under nohup in which case stdin won't exist.
    pyterm = Popen(
        f"python3 tools/deploy/term.py {args.mote} --mote-type {args.mote_type} --log-dir {args.log_dir}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(pyterm,
             stdout=[pcap_monitor, pyterm_log, StreamNoTimestamp(sys.stdout)],
             stderr=[pcap_monitor, pyterm_log, StreamNoTimestamp(sys.stderr)])
    teed.wait()
    pyterm.wait()
    print("pyterm finished!", flush=True)
