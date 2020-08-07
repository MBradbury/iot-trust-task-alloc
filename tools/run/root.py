#!/usr/bin/env python3

import argparse
import subprocess
import time
import os

from util import Teed

DEFAULT_LOG_DIR = "~/iot-trust-task-alloc/logs"

parser = argparse.ArgumentParser(description='Root runner')
parser.add_argument('--log-dir', type=str, default=DEFAULT_LOG_DIR, help='The directory to store log output')
args = parser.parse_args()

if args.log_dir.startswith("~"):
    args.log_dir = os.path.expanduser(args.log_dir)

# Create log dir if it does not exist
if not os.path.isdir(args.log_dir):
    os.makedirs(args.log_dir)

hostname = os.uname()[1]

tunslip_log_path = os.path.join(args.log_dir, f"root.{hostname}.tunslip.log")
service_log_path = os.path.join(args.log_dir, f"root.{hostname}.service.log")
root_server_log_path = os.path.join(args.log_dir, f"root.{hostname}.root_server.log")

print(f"Logging tunslip to {tunslip_log_path}")
print(f"Logging root_server to {root_server_log_path}")

with open(tunslip_log_path, 'w') as tunslip_log, \
     open(service_log_path, 'w') as service_log, \
     open(root_server_log_path, 'w') as root_server_log:

    teed = Teed()

    tunslip = subprocess.Popen(
        "sudo ./tunslip6 -s /dev/ttyUSB0 fd00::1/64",
        cwd=os.path.expanduser("~/contiki-ng/tools/serial-io"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(tunslip, stdout=tunslip_log, stderr=tunslip_log)

    time.sleep(2)

    service = subprocess.Popen(
        "sudo service mosquitto restart",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(service, stdout=service_log, stderr=service_log)
    service.wait()

    time.sleep(2)

    root_server = subprocess.Popen(
        "./root_server.py -k keystore",
        cwd=os.path.expanduser("~/iot-trust-task-alloc/resource_rich/root"),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        encoding="utf-8",
    )
    teed.add(root_server, stdout=root_server_log, stderr=root_server_log)

    teed.wait()
    root_server.wait()
    tunslip.wait()
