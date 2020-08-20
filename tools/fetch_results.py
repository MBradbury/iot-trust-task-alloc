#!/usr/bin/env python3

#import getpass
import os
import sys

import subprocess


ips = {
    "wsn1": "fd00::1",
    "wsn2": "fd00::212:4b00:14d5:2bd6", # 00:12:4B:00:14:D5:2B:D6
    "wsn3": "fd00::212:4b00:14d5:2ddb", # 00:12:4B:00:14:D5:2D:DB
    "wsn4": "fd00::212:4b00:14d5:2be6", # 00:12:4B:00:14:D5:2B:E6
    "wsn5": "fd00::212:4b00:14b5:da27", # 00:12:4B:00:14:B5:DA:27
    "wsn6": "fd00::212:4b00:14d5:2f05", # 00:12:4B:00:14:D5:2F:05
}

#password = getpass.getpass("Password: ")

if not os.path.isdir("results"):
    os.makedirs("results")

for hostname in ips.keys():
    print(f"Fetching results for {hostname}...")
    subprocess.run(
        f'rsync pi@{hostname}:/home/pi/iot-trust-task-alloc/logs/* ./results',
        shell=True)
