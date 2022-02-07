#!/usr/bin/env python3

import argparse
import subprocess
import time
import os
import sys
import pathlib

from common.configuration import devices

from tools.run import supported_mote_types, supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import Teed, Popen, StreamNoTimestamp
from tools.keygen.util import eui64_to_ipv6

parser = argparse.ArgumentParser(description='Profile runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
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

motelist_log_path = os.path.join(args.log_dir, f"profile.{hostname}.motelist.log")
flash_log_path = os.path.join(args.log_dir, f"profile.{hostname}.flash.log")
pyterm_log_path = os.path.join(args.log_dir, f"profile.{hostname}.pyterm.log")

print(f"CWD: {os.getcwd()}", flush=True)
print(f"Logging motelist to {motelist_log_path}", flush=True)
print(f"Logging flash to {flash_log_path}", flush=True)
print(f"Logging pyterm to {pyterm_log_path}", flush=True)

# Get the device connected to this host
devices = [dev for dev in devices if dev.hostname == hostname]
if not devices:
    raise RuntimeError(f"No devices configured for this host {hostname} in the configuration")
if len(devices) > 1:
    raise RuntimeError(f"More than one device configured for this host {hostname} in the configuration")
(device,) = devices

with open(motelist_log_path, 'w') as motelist_log:
    teed = Teed()
    motelist = Popen(
        f"python3 -m tools.deploy.motelist --mote-type {device.kind.value}",
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

    if motelist.returncode != 0:
        raise RuntimeError("Motelist failed")

time.sleep(0.1)

device_firmware_dir = str(eui64_to_ipv6(device.eui64)).replace(":", "_")
firmware_path = pathlib.Path.cwd() / 'setup' / device_firmware_dir / 'profile.bin'

with open(flash_log_path, 'w') as flash_log:
    teed = Teed()
    flash = Popen(
        f"python3 flash.py '{device.identifier}' '{firmware_path}' {device.kind.value} {args.firmware_type}",
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

    if flash.returncode != 0:
        raise RuntimeError("Flashing failed")
    else:
        print("Flashing finished!", flush=True)

time.sleep(0.1)

with open(pyterm_log_path, 'w') as pyterm_log:
    teed = Teed()

    # stdin=subprocess.PIPE is needed in order to ensure that a stdin handle exists.
    # This is because this script may be called under nohup in which case stdin won't exist.
    pyterm = Popen(
        f"python3 tools/deploy/term.py {device.identifier} {device.kind.value} --log-dir {args.log_dir}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(pyterm,
             stdout=[pyterm_log, StreamNoTimestamp(sys.stdout)],
             stderr=[pyterm_log, StreamNoTimestamp(sys.stderr)])
    teed.wait()
    pyterm.wait()

    if pyterm.returncode != 0:
        raise RuntimeError("pyterm failed")
    else:
        print("pyterm finished!", flush=True)
    
