#!/usr/bin/env python

import sys
import getpass
import os

from fabric import SerialGroup as Group

hosts = [
    "wsn1",
    "wsn2",
    "wsn3",
    "wsn4",
]

source = sys.argv[1]
target = os.path.join("/home/pi/pi-client", os.path.basename(source))

if not os.path.exists(source):
    raise FileNotFoundError(f"{source} does not exist")

print(f"Copying '{source}' -> {target} ...")

password = getpass.getpass("Password: ")

with Group(*hosts, user="pi", connect_kwargs={"password": password}) as pool:
    for conn in pool:
        result = conn.put(source, target)
        print("Uploaded {0.local} to {0.remote} for {1}".format(result, conn))
