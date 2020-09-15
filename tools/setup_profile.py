#!/usr/bin/env python3

import argparse
import subprocess
from datetime import datetime, timezone
import shutil
import pathlib
import getpass
import os
import ipaddress
import secrets
from more_itertools import chunked

import fabric
import patchwork.transfers

from common.stereotype_tags import StereotypeTags, DeviceClass
from tools.keygen.keygen import generate_and_save_key
from tools.keygen.contiking_format import *
from common.certificate import TBSCertificate, SignedCertificate
from common.configuration import hostname_to_ips as ips, root_node, device_stereotypes

root_ip = ips[root_node]

class Setup:
    def __init__(self):
        self.build_number = 1

        self.binaries = ["profile"]

        self.keys = None
        self.certs = None

        self.certificate_serial_number = 0

        self.oscore_master_salt = bytes.fromhex("642b2b8e9d0c4263924ceafcf7038b26")
        self.oscore_id_context = None

        self.oscore_id_len = 6

    def run(self):
        self._create_setup_dir()

        print("Cleaning directories")
        self._clean_build_dirs()

        print("Building keystore")
        self._build_keystore()
        self._create_certificates()

        self._generate_static_keys_and_build()


        password = getpass.getpass("Password: ")

        print("Deploying build binaries to targets")
        self._deploy(password)

        print(f"Finished setup profile deployment!")

    @staticmethod
    def bytes_to_c_array(b: bytes) -> str:
        return '"{' + ', '.join(f"0x{''.join(h)}" for h in chunked(b.hex(), 2)) + '}"'

    @staticmethod
    def ip_name(ip: str) -> str:
        return ip.replace(":", "_")

    def _create_setup_dir(self):
        if os.path.exists("setup"):
            with open("setup/build_number", "r") as build_number_file:
                self.build_number = int(build_number_file.read()) + 1

            print("Removing setup directory")
            shutil.rmtree("setup")

        print(f"Using build number {self.build_number}")
        pathlib.Path(f"setup").mkdir(parents=True, exist_ok=False)
        with open("setup/build_number", "w") as build_number_file:
            print(f"{self.build_number}", file=build_number_file)

    def _clean_build_dirs(self):
        for binary in self.binaries:
            subprocess.run(
                f"make distclean -C wsn/{binary}",
                shell=True,
                check=True,
                capture_output=True
            )

    def _build_keystore(self):
        self.keys = {
            ip: generate_and_save_key("setup/keystore", ip)
            for ip
            in ips.values()
        }

        # Clarify the root server's private key
        shutil.copy(f"setup/keystore/{self.ip_name(root_ip)}-private.pem", "setup/keystore/private.pem")

    def ip_to_eui64(self, subject: str) -> bytes:
        ip = ipaddress.ip_address(subject)

        # Last 8 bytes of the ip address
        eui64 = bytearray(int(ip).to_bytes(16, byteorder='big')[-8:])

        # See: uip_ds6_set_lladdr_from_iid
        if subject != root_ip:
            eui64[0] ^= 0x02

        return bytes(eui64)

    def create_certificate(self, subject: str, stereotype_tags: StereotypeTags) -> SignedCertificate:
        tbscert = TBSCertificate(
            serial_number=self.certificate_serial_number,
            issuer=self.ip_to_eui64(root_ip),
            validity_from=0,
            validity_to=None,
            subject=self.ip_to_eui64(subject),
            stereotype_tags=stereotype_tags,
            public_key=self.keys[subject].public_key(),
        )

        self.certificate_serial_number += 1

        return tbscert.build(self.keys[root_ip])

    def create_and_save_certificate(self, keystore_dir: str, subject: str, stereotype_tags: StereotypeTags) -> SignedCertificate:
        cert = self.create_certificate(subject, stereotype_tags)

        pathlib.Path(keystore_dir).mkdir(parents=True, exist_ok=True)

        prefix = subject.replace(":", "_")

        with open(f"{keystore_dir}/{prefix}-cert.iot-trust-cert", 'wb') as cert_out:
            cert_out.write(cert.encode())

        return cert

    def _create_certificates(self):
        self.certs = {
            ip: self.create_and_save_certificate("setup/keystore", ip, device_stereotypes[name])
            for name, ip
            in sorted(ips.items(), key=lambda x: x[0])
        }

    def create_static_keys(self, ip):
        with open("setup/static-keys.c", "w") as static_keys:
            print(f'// Generated at {datetime.now(timezone.utc)}', file=static_keys)
            print('#include "certificate.h"', file=static_keys)
            print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
            print(contiking_format_our_privkey(self.keys[ip], ip), file=static_keys)
            print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
            print(contiking_format_certificate(self.certs[root_ip], "root_cert", root_ip), file=static_keys)
            print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)
            print(contiking_format_certificate(self.certs[ip], "our_cert", ip), file=static_keys)
            print('/*-------------------------------------------------------------------------------------------------------------------*/', file=static_keys)

    def _generate_static_keys_and_build(self):
        # Back-up static-keys.c
        if os.path.exists("wsn/common/crypto/static-keys.c"):
            shutil.move("wsn/common/crypto/static-keys.c", "wsn/common/crypto/static-keys.c.orig")

        for (target, ip) in ips.items():
            # Skip building for root ip
            if ip == root_ip:
                continue

            print(f"Building for {ip} attached to {target}")

            name = self.ip_name(ip)
            pathlib.Path(f"setup/{name}").mkdir(parents=True, exist_ok=True)

            print(f"Creating static-keys.c for {ip}")
            self.create_static_keys(ip)
            shutil.move("setup/static-keys.c", "wsn/common/crypto/static-keys.c")

            build_args = {
                "BUILD_NUMBER": "0",
            }

            if self.oscore_master_salt is not None:
                build_args["OSCORE_MASTER_SALT"] = self.bytes_to_c_array(self.oscore_master_salt)

            if self.oscore_id_context is not None:
                build_args["OSCORE_ID_CONTEXT"] = self.bytes_to_c_array(self.oscore_id_context)

            build_args_str = " ".join(f"{k}={v}" for (k,v) in build_args.items())

            for binary in self.binaries:
                print(f"Building {binary} with '{build_args}'")
                subprocess.run(f"make -C wsn/{binary} {build_args_str}", shell=True, check=True)
                shutil.move(f"wsn/{binary}/build/zoul/remote-revb/{binary}.bin", f"setup/{name}/{binary}.bin")

            shutil.move("wsn/common/crypto/static-keys.c", f"setup/{name}/static-keys.c")

        # Move backed-up static-keys.c back
        if os.path.exists("wsn/common/crypto/static-keys.c.orig"):
            shutil.move("wsn/common/crypto/static-keys.c.orig", "wsn/common/crypto/static-keys.c")

    def _deploy(self, password: str):
        for (target, ip) in ips.items():
            with fabric.Connection(f'pi@{target}', connect_kwargs={"password": password}) as conn:
                # Now upload the configuration
                src = f"common/configuration.py"
                dest = os.path.join("/home/pi/iot-trust-task-alloc", src)
                result = conn.put(src, dest)
                print("Uploaded {0.local} to {0.remote} for {1}".format(result, conn))

                # Skip deploying binaries for root ip
                if ip == root_ip:
                    continue

                for binary in self.binaries:
                    src = f"setup/{self.ip_name(ip)}/{binary}.bin"
                    dest = os.path.join("/home/pi/pi-client", os.path.basename(src))

                    result = conn.put(src, dest)
                    print("Uploaded {0.local} to {0.remote} for {1}".format(result, conn))

if __name__ == "__main__":
    setup = Setup()
    setup.run()
