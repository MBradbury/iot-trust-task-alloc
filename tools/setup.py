#!/usr/bin/env python3

import subprocess
from datetime import datetime
import shutil
import pathlib
import getpass
import os

import  fabric
import patchwork.transfers

import eckeygen

ips = {
    "wsn1": "fd00::1",
    "wsn2": "fd00::212:4b00:14d5:2bd6",
    "wsn3": "fd00::212:4b00:14d5:2ba9",
    "wsn4": "fd00::212:4b00:14d5:2be6",
}

binaries = ["node", "edge"]

root_node = "wsn1"
root_ip = "fd00::1"

if os.path.exists("setup"):
    with open("setup/build_number", "r") as build_number_file:
        build_number = int(build_number_file.read()) + 1

    print("Removing setup directory")
    shutil.rmtree("setup")
else:
    build_number = 1

print(f"Using build number {build_number}")
pathlib.Path(f"setup").mkdir(parents=True, exist_ok=False)
with open("setup/build_number", "w") as build_number_file:
    print(f"{build_number}", file=build_number_file)


print("Cleaning directories")
for binary in binaries:
    subprocess.run(f"make distclean -C wsn/{binary}", shell=True, check=True, capture_output=True)

print("Building keystore")
keys = {
    ip: eckeygen.main(ip, "setup/keystore")
    for ip
    in ips.values()
}

def ip_name(ip):
    return ip.replace(":", "_")

def create_static_keys(ip):
    with open("setup/static-keys.c", "w") as static_keys:
        print(f'// Generated at {datetime.now()}', file=static_keys)
        print('#include "keys.h"', file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(eckeygen.contiking_format_our_key(keys[ip], ip), file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(eckeygen.contiking_format_our_key_cert(keys[ip], keys[root_ip], ip, root_ip), file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(eckeygen.contiking_format_root_key(keys[root_ip], root_ip), file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)

# Back-up static-keys.c
if os.path.exists("wsn/common/crypto/static-keys.c"):
    shutil.move("wsn/common/crypto/static-keys.c", "wsn/common/crypto/static-keys.c.orig")

for (target, ip) in ips.items():
    # Skip building for root ip
    if ip == root_ip:
        continue

    print(f"Building for {ip} attached to {target}")

    name = ip_name(ip)
    pathlib.Path(f"setup/{name}").mkdir(parents=True, exist_ok=True)

    print(f"Creating static-keys.c for {ip}")
    create_static_keys(ip)
    shutil.move("setup/static-keys.c", "wsn/common/crypto/static-keys.c")

    for binary in binaries:
        print(f"Building {binary}")
        subprocess.run(f"make -C wsn/{binary} BUILD_NUMBER={build_number}", shell=True, check=True)
        shutil.move(f"wsn/{binary}/build/zoul/remote-revb/{binary}.bin", f"setup/{name}/{binary}.bin")

    shutil.move("wsn/common/crypto/static-keys.c", f"setup/{name}/static-keys.c")

# Move backed-up static-keys.c back
if os.path.exists("wsn/common/crypto/static-keys.c.orig"):
    shutil.move("wsn/common/crypto/static-keys.c.orig", "wsn/common/crypto/static-keys.c")

print("Deploying build binaries to targets")

password = getpass.getpass("Password: ")

for (target, ip) in ips.items():
    # Skip deploying binaries for root ip
    if ip == root_ip:
        continue

    name = ip_name(ip)

    with fabric.Connection(f'pi@{target}', connect_kwargs={"password": password}) as conn:
        for binary in binaries:
            src = f"setup/{name}/{binary}.bin"
            dest = os.path.join("/home/pi/pi-client", os.path.basename(src))

            result = conn.put(src, dest)
            print("Uploaded {0.local} to {0.remote} for {1}".format(result, conn))


print("Tidying up keystore")

# Clarify the root server's private key
shutil.move(f"setup/keystore/{ip_name(root_ip)}-private.pem", "setup/keystore/private.pem")

# Remove its public key (as this is contained within the private key file)
os.remove(f"setup/keystore/{ip_name(root_ip)}-public.pem")

# Remove the private keys of the sensor nodes
for ip in ips.values():
    # Skip root ip
    if ip == root_ip:
        continue

    os.remove(f"setup/keystore/{ip_name(ip)}-private.pem")

print("Deploying keystore to root")

with fabric.Connection(f'pi@{root_node}', connect_kwargs={"password": password}) as conn:
    src = "./setup/keystore"
    dest = "/home/pi/iot-trust-task-alloc/root"

    patchwork.transfers.rsync(conn, src, dest, rsync_opts="-r")

print(f"Finished setup deployment (build={build_number})!")
