#!/usr/bin/env python3

import argparse
import subprocess
import time
import os
import sys
import pathlib

from common.configuration import devices

from tools.deploy.motedev import get_mote_device
from tools.run import supported_mote_types, supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import Teed, Popen, StreamNoTimestamp

parser = argparse.ArgumentParser(description='Root runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')

# Flash.py
parser.add_argument("--firmware-type",
                    choices=supported_firmware_types,
                    default=supported_firmware_types[0],
                    help="The OS that was used to create the firmware.")

parser.add_argument("--no-flush-oscore", action="store_true", default=False, help="Disable flushing OSCORE cache")

args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

motelist_log_path = os.path.join(args.log_dir, f"root.{hostname}.motelist.log")
flash_log_path = os.path.join(args.log_dir, f"root.{hostname}.flash.log")
tunslip_log_path = os.path.join(args.log_dir, f"root.{hostname}.tunslip.log")
service_log_path = os.path.join(args.log_dir, f"root.{hostname}.service.log")
root_server_log_path = os.path.join(args.log_dir, f"root.{hostname}.root_server.log")

print(f"CWD: {os.getcwd()}", flush=True)
print(f"Logging motelist to {motelist_log_path}", flush=True)
print(f"Logging tunslip to {tunslip_log_path}", flush=True)
print(f"Logging root_server to {root_server_log_path}", flush=True)

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

firmware_path = pathlib.Path.cwd() / "setup" / "border-router.bin"

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

# By default we need to remove the OSCORE state storing the cached sequence numbers
if not args.no_flush_oscore:
    print("Removing cached OSCORE state", flush=True)

    oscore_contexts_dir = "resource_rich/root/keystore/oscore-contexts"
    for content in os.listdir(oscore_contexts_dir):
        print(f"Removing {oscore_contexts_dir}/{content}/sequence.json", flush=True)
        try:
            os.remove(f"{oscore_contexts_dir}/{content}/sequence.json")
        except FileNotFoundError:
            pass

com_port = get_mote_device(device.identifier, device.kind.value)
print(f"Found com port {com_port} for device {device}", flush=True)

with open(tunslip_log_path, 'w') as tunslip_log, \
     open(service_log_path, 'w') as service_log, \
     open(root_server_log_path, 'w') as root_server_log:

    teed = Teed()

    tunslip = Popen(
        f"sudo ./tunslip6 -s '{com_port}' fd00::1/64",
        cwd=os.path.expanduser("~/deploy/contiki-ng/tools/serial-io"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(tunslip,
             stdout=[tunslip_log, StreamNoTimestamp(sys.stdout)],
             stderr=[tunslip_log, StreamNoTimestamp(sys.stderr)])

    time.sleep(2)

    service = Popen(
        "sudo service mosquitto restart",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(service,
             stdout=[service_log, StreamNoTimestamp(sys.stdout)],
             stderr=[service_log, StreamNoTimestamp(sys.stderr)])
    service.wait()
    if service.returncode != 0:
        raise RuntimeError("mosquitto restart failed")
    else:
        print("mosquitto restart finished!", flush=True)

    time.sleep(2)

    root_server = Popen(
        "python3 -m resource_rich.root.root_server -k resource_rich/root/keystore",
        cwd=os.path.expanduser("~/deploy/iot-trust-task-alloc"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(root_server,
             stdout=[root_server_log, StreamNoTimestamp(sys.stdout)],
             stderr=[root_server_log, StreamNoTimestamp(sys.stderr)])

    teed.wait()
    root_server.wait()
    tunslip.wait()
