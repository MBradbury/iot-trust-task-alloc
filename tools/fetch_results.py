#!/usr/bin/env python3

import getpass
import sys
import subprocess
import argparse
import pathlib
import pexpect

from common.configuration import hostname_to_ips as ips, root_node

parser = argparse.ArgumentParser(description='Fetch Results')
parser.add_argument('target', type=pathlib.Path, help='The target directory to save results to')
args = parser.parse_args()

password = getpass.getpass("Password: ")

# Create the target
args.target.mkdir(parents=True, exist_ok=True)

print(f"Saving to {args.target}")

# Also very important to fetch the keystore, in order to faciltate decrypting the results
print(f"Fetching keystore from root node on {root_node}")
child = pexpect.spawn(f"bash -c 'rsync -avz pi@{root_node}:/home/pi/iot-trust-task-alloc/resource_rich/root/keystore/ {args.target/'keystore'}'")
child.expect('password:')
child.sendline(password)

for hostname in ips.keys():
    print(f"Fetching results for {hostname}...")
    child = pexpect.spawn(f"bash -c 'rsync -avz pi@{hostname}:/home/pi/iot-trust-task-alloc/logs/* {args.target}'")
    child.expect('password:')
    child.sendline(password)
