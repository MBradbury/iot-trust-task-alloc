#!/usr/bin/env python3

import argparse
import subprocess
from datetime import datetime
import shutil
import pathlib
import getpass
import os
import sys
import ipaddress

import fabric
import patchwork.transfers

from common.stereotype_tags import StereotypeTags, DeviceClass
from tools.keygen.keygen import generate_and_save_key
from tools.keygen.contiking_format import *
from common.certificate import TBSCertificate

available_trust_models = [x for x in os.listdir("wsn/common/trust/models") if not x.endswith(".h")]
available_trust_chooses = [x for x in os.listdir("wsn/common/trust/choose") if not x.endswith(".h")]

parser = argparse.ArgumentParser(description='Setup')
parser.add_argument('trust_model', type=str, choices=available_trust_models, help='The trust model to use')
parser.add_argument('trust_choose', type=str, choices=available_trust_chooses, help='The trust choose to use')
parser.add_argument('--with-pcap', action='store_true', help='Enable capturing and outputting pcap dumps from the nodes')
args = parser.parse_args()

print(f"Using trust model {args.trust_model}")

ips = {
    "wsn1": "fd00::1",
    "wsn2": "fd00::212:4b00:14d5:2bd6", # 00:12:4B:00:14:D5:2B:D6
    "wsn3": "fd00::212:4b00:14d5:2ddb", # 00:12:4B:00:14:D5:2D:DB
    "wsn4": "fd00::212:4b00:14d5:2be6", # 00:12:4B:00:14:D5:2B:E6
    "wsn5": "fd00::212:4b00:14b5:da27", # 00:12:4B:00:14:B5:DA:27
    "wsn6": "fd00::212:4b00:14d5:2f05", # 00:12:4B:00:14:D5:2F:05
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
    subprocess.run(f"make distclean -C wsn/{binary} TRUST_MODEL={args.trust_model} TRUST_CHOOSE={args.trust_choose}", shell=True, check=True, capture_output=True)

def ip_name(ip):
    return ip.replace(":", "_")

print("Building keystore")
keys = {
    ip: generate_and_save_key("setup/keystore", ip)
    for ip
    in ips.values()
}

def ip_to_eui64(subject):
    ip = ipaddress.ip_address(subject)

    # Last 8 bytes of the ip address
    eui64 = bytearray(int(ip).to_bytes(16, byteorder='big')[-8:])

    # See: uip_ds6_set_lladdr_from_iid
    if subject != root_ip:
        eui64[0] ^= 0x02

    return bytes(eui64)

serial_number = 0

def create_certificate(subject):
    global serial_number

    tags = StereotypeTags(
        device_class=DeviceClass.RASPBERRY_PI
    )

    tbscert = TBSCertificate(
        serial_number=serial_number,
        issuer=ip_to_eui64(root_ip),
        validity_from=0,
        validity_to=None,
        subject=ip_to_eui64(subject),
        stereotype_tags=tags,
        public_key=keys[subject].public_key(),
    )

    serial_number += 1

    return tbscert.build(keys[root_ip])

def create_and_save_certificate(keystore_dir, subject):
    cert = create_certificate(subject)

    pathlib.Path(keystore_dir).mkdir(parents=True, exist_ok=True)

    prefix = subject.replace(":", "_")

    with open(f"{keystore_dir}/{prefix}-cert.iot-trust-cert", 'wb') as cert_out:
        cert_out.write(cert.encode())

    return cert

certs = {
    ip: create_and_save_certificate("setup/keystore", ip)
    for name, ip
    in sorted(ips.items(), key=lambda x: x[0])
}

print("Creating OSCORE contexts")

oscore_context_dir = "setup/keystore/oscore-contexts"

for ip, cert in certs.items():
    # Skip root ip
    if ip == root_ip:
        continue

    sender_id = certs[root_ip].subject[-6:]
    recipient_id = cert.subject[-6:]

    shared_secret = keys[root_ip].exchange(ec.ECDH(), keys[ip].public_key())

    pathlib.Path(f'{oscore_context_dir}/{recipient_id.hex()}').mkdir(parents=True, exist_ok=False)

    with open(f'{oscore_context_dir}/{recipient_id.hex()}/secret.json', 'w') as secret:
        print('{', file=secret)
        print('    "algorithm": "AES-CCM-16-64-128",', file=secret)
        print('    "kdf-hashfun": "sha256",', file=secret)
        print('    "window": 32,', file=secret)
        print(f'    "sender-id_hex": "{sender_id.hex()}",', file=secret)
        print(f'    "recipient-id_hex": "{recipient_id.hex()}",', file=secret)
        print(f'    "secret_hex": "{shared_secret.hex()}"', file=secret)
        # No master salt
        # No id-context
        print('}', file=secret)


def create_static_keys(ip):
    with open("setup/static-keys.c", "w") as static_keys:
        print(f'// Generated at {datetime.now()}', file=static_keys)
        print('#include "certificate.h"', file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(contiking_format_our_privkey(keys[ip], ip), file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(contiking_format_certificate(certs[root_ip], "root_cert", root_ip), file=static_keys)
        print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
        print(contiking_format_certificate(certs[ip], "our_cert", ip), file=static_keys)
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

    build_args = {
        "BUILD_NUMBER": build_number,
        "TRUST_MODEL": args.trust_model,
        "TRUST_CHOOSE": args.trust_choose,
    }

    if args.with_pcap:
        build_args["MAKE_WITH_PCAP"] = "1"

    build_args_str = " ".join(f"{k}={v}" for (k,v) in build_args.items())

    for binary in binaries:
        print(f"Building {binary} with '{build_args}'")
        subprocess.run(f"make -C wsn/{binary} {build_args_str}", shell=True, check=True)
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
    dest = "/home/pi/iot-trust-task-alloc/resource_rich/root"

    patchwork.transfers.rsync(conn, src, dest, rsync_opts="-r")

print(f"Finished setup deployment (build={build_number})!")
