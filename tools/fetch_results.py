#!/usr/bin/env python3

#import getpass
import os
import sys

import subprocess

from common.configuration import hostname_to_ips as ips

#password = getpass.getpass("Password: ")

if not os.path.isdir("results"):
    os.makedirs("results")

# Also very important to fetch the keystore, in order to faciltate decrypting the results
print("Fetching keystore")
subprocess.run(
    f'rsync -avz pi@wsn1:/home/pi/iot-trust-task-alloc/resource_rich/root/keystore/ ./results/keystore',
    shell=True)

for hostname in ips.keys():
    print(f"Fetching results for {hostname}...")
    subprocess.run(
        f'rsync -avz pi@{hostname}:/home/pi/iot-trust-task-alloc/logs/* ./results',
        shell=True)
