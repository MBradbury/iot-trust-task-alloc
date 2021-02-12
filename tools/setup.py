#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from datetime import datetime, timezone
import shutil
import pathlib
import getpass
import os
import os.path
import ipaddress
import secrets
import itertools
from more_itertools import chunked
import json

import fabric
import patchwork.transfers

from common.stereotype_tags import StereotypeTags, DeviceClass
from tools.keygen.keygen import generate_and_save_key
from tools.keygen.contiking_format import *
from tools.keygen.util import ip_to_eui64
from common.certificate import TBSCertificate, SignedCertificate
from common.configuration import hostname_to_ips as ips, root_node, device_stereotypes

root_ip = ips[root_node]

class Setup:

    # See: wsn/common/crypto/keystore.c for the corresponding definition
    oscore_id_len = 6

    oscore_algorithm = "AES-CCM-16-64-128"

    def __init__(self, trust_model: str, trust_choose: str, applications: list[str], with_pcap: bool, with_adversary: list[str], defines: dict[str, str]):
        self.trust_model = trust_model
        self.trust_choose = trust_choose
        self.applications = applications
        self.with_pcap = with_pcap
        self.with_adversary = with_adversary
        self.defines = defines

        self.build_number = 1

        self.binaries = ["node", "edge"]
        if self.with_adversary:
            self.binaries.append("adversary")

        self.keys = None
        self.certs = None

        self.certificate_serial_number = 0

        # For simplicity and determinism keep with the same salt
        #self.oscore_master_salt = secrets.token_bytes(16)
        self.oscore_master_salt = bytes.fromhex("642b2b8e9d0c4263924ceafcf7038b26")

        # Not sure why, but having no id context seems to work
        # Possibly an issue with interaction of aiocoap and Contiki-NG's OSCORE
        #self.oscore_id_context = b"\x01"
        self.oscore_id_context = None

    def run(self):
        print(f"Using trust model {self.trust_model}")
        self._create_setup_dir()

        print("Cleaning directories")
        self._clean_build_dirs()

        print("Building keystore")
        self._build_keystore()
        self._create_certificates()

        print("Creating OSCORE contexts")
        self._create_oscore_contexts()

        self._generate_static_keys_and_build()

        password = getpass.getpass("Password: ")

        print("Deploying build binaries to targets")
        self._deploy(password)

        print("Deploying keystore to root")
        self._deploy_keystore(password)

        print(f"Finished setup deployment (build={self.build_number})!")

    @staticmethod
    def bytes_to_c_array(b: bytes) -> str:
        return '"{' + ', '.join(f"0x{''.join(h)}" for h in chunked(b.hex(), 2)) + '}"'

    @staticmethod
    def ip_name(ip: ipaddress.IPv6Address) -> str:
        return str(ip).replace(":", "_")

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
                f"make distclean -C wsn/{binary} TRUST_MODEL={self.trust_model} TRUST_CHOOSE={self.trust_choose} MAKE_ATTACKS=dummy",
                shell=True,
                check=True,
                capture_output=True
            )

    def _build_keystore(self):
        self.keys = {
            ip: generate_and_save_key("setup/keystore", str(ip))
            for ip
            in ips.values()
        }

        # Clarify the root server's private key
        shutil.copy(f"setup/keystore/{self.ip_name(root_ip)}-private.pem", "setup/keystore/private.pem")

    def create_certificate(self, subject: ipaddress.IPv6Address, stereotype_tags: StereotypeTags) -> SignedCertificate:
        tbscert = TBSCertificate(
            serial_number=self.certificate_serial_number,
            issuer=ip_to_eui64(root_ip, root_ip=root_ip),
            validity_from=0,
            validity_to=None,
            subject=ip_to_eui64(subject, root_ip=root_ip),
            stereotype_tags=stereotype_tags,
            public_key=self.keys[subject].public_key(),
        )

        self.certificate_serial_number += 1

        return tbscert.build(self.keys[root_ip])

    def create_and_save_certificate(self, keystore_dir: str, subject: ipaddress.IPv6Address, stereotype_tags: StereotypeTags) -> SignedCertificate:
        cert = self.create_certificate(subject, stereotype_tags)

        pathlib.Path(keystore_dir).mkdir(parents=True, exist_ok=True)

        prefix = self.ip_name(subject)

        with open(f"{keystore_dir}/{prefix}-cert.iot-trust-cert", 'wb') as cert_out:
            cert_out.write(cert.encode())

        return cert

    def _create_certificates(self):
        self.certs = {
            ip: self.create_and_save_certificate("setup/keystore", ip, device_stereotypes[name])
            for name, ip
            in sorted(ips.items(), key=lambda x: x[0])
        }

    def certificate_oscore_id(self, certificate: SignedCertificate) -> bytes:
        return certificate.subject[-self.oscore_id_len:]

    def _create_oscore_contexts(self):
        oscore_context_dir = "setup/keystore/oscore-contexts"

        if self.oscore_master_salt is not None:
            print(f"OSCORE Master Salt: {self.oscore_master_salt.hex()}")
        if self.oscore_id_context is not None:
            print(f"OSCORE ID Context: {self.oscore_id_context.hex()}")

        for ip, cert in self.certs.items():
            # Skip root ip
            if ip == root_ip:
                continue

            sender_id = self.certificate_oscore_id(self.certs[root_ip])
            recipient_id = self.certificate_oscore_id(cert)

            shared_secret = self.keys[root_ip].exchange(ec.ECDH(), self.keys[ip].public_key())

            pathlib.Path(f'{oscore_context_dir}/{recipient_id.hex()}').mkdir(parents=True, exist_ok=False)

            with open(f'{oscore_context_dir}/{recipient_id.hex()}/secret.json', 'w', encoding="utf-8") as secret:

                secret_json = {
                    "algorithm": self.oscore_algorithm,
                    "kdf-hashfun": "sha256",
                    "window": 32,
                    "sender-id_hex": sender_id.hex(),
                    "recipient-id_hex": recipient_id.hex(),
                    "secret_hex": shared_secret.hex(),
                }

                if self.oscore_master_salt is not None:
                    secret_json["salt_hex"] = self.oscore_master_salt.hex()

                if self.oscore_id_context is not None:
                    secret_json["id-context_hex"] = self.oscore_id_context.hex()

                json.dump(secret_json, secret, indent=4)

        # Also create the Wireshark configuration to allow these messages to be decrypted
        self._write_oscore_context_pref()

    def _write_oscore_context_pref(self):
        # Need to write a file that allows wireshark to decrypt OSCORE messages
        # File is comma separated with # as a comment, e.g.,
        """
        # This file is automatically generated, DO NOT MODIFY.
        "1","1","1","1","","AES-CCM-16-64-128 (CCM*)"
        "1","1","1","1","","AES-CCM-16-64-128 (CCM*)"
        """
        # Parameters are:
        # Sender ID, Recipient ID, Master Secret, Master Salt, ID Context, Algorithm
        # See: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-oscore.c#L871

        # See: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-oscore.c#L74
        aiocoap_to_tshark_algorithm = {
            "AES-CCM-16-64-128": "AES-CCM-16-64-128 (CCM*)"
        }

        with open(os.path.abspath(f'setup/keystore/oscore.contexts.uat'), "w") as tshark_oscore_conf:
            for sender, recipient in itertools.permutations(ips.values(), 2):
                if sender == recipient:
                    continue

                sender_id = self.certificate_oscore_id(self.certs[sender])
                recipient_id = self.certificate_oscore_id(self.certs[recipient])

                shared_secret = self.keys[sender].exchange(ec.ECDH(), self.keys[recipient].public_key())

                line = [
                    sender_id.hex(),
                    recipient_id.hex(),
                    shared_secret.hex(),
                    self.oscore_master_salt if self.oscore_master_salt is not None else "",
                    self.oscore_id_context if self.oscore_id_context is not None else "",
                    aiocoap_to_tshark_algorithm[self.oscore_algorithm]
                ]

                print(','.join(f'"{v}"' for v in line), file=tshark_oscore_conf)

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
                "BUILD_NUMBER": self.build_number,
                "TRUST_MODEL": self.trust_model,
                "TRUST_CHOOSE": self.trust_choose,
                "TARGET": "zoul",
                "PLATFORM": "remote-revb",
                "APPLICATIONS": '"' + " ".join(self.applications) + '"',
            }

            if self.with_pcap:
                build_args["MAKE_WITH_PCAP"] = "1"

            if self.oscore_master_salt is not None:
                build_args["OSCORE_MASTER_SALT"] = self.bytes_to_c_array(self.oscore_master_salt)

            if self.oscore_id_context is not None:
                build_args["OSCORE_ID_CONTEXT"] = self.bytes_to_c_array(self.oscore_id_context)

            if self.defines:
                build_args["ADDITIONAL_CFLAGS"] = '"' + " ".join([f"-D{k}={v}" for (k,v) in self.defines.items()]) + '"'

            for binary in self.binaries:
                print(f"Building {binary} with '{build_args}'")

                final_build_args = {**build_args}

                if binary == "adversary" and self.with_adversary:
                    final_build_args["MAKE_ATTACKS"] = ",".join(self.with_adversary)

                build_args_str = " ".join(f"{k}={v}" for (k,v) in final_build_args.items())

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

    def _deploy_keystore(self, password: str):
        with fabric.Connection(f'pi@{root_node}', connect_kwargs={"password": password}) as conn:
            src = "./setup/keystore"
            dest = "/home/pi/iot-trust-task-alloc/resource_rich/root"

            patchwork.transfers.rsync(conn, src, dest, rsync_opts="-r")

if __name__ == "__main__":
    import argparse

    # From: https://stackoverflow.com/questions/8526675/python-argparse-optional-append-argument-with-choices
    class DefinesAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if values:
                if len(values) != 2:
                    raise argparse.ArgumentError(self, f"Must have two arguments {values}")

                name, value = values

                attr = getattr(namespace, self.dest)
                if attr is None:
                    setattr(namespace, self.dest, {name: value})
                else:
                    attr[name] = value

    available_trust_models = [x for x in os.listdir("wsn/common/trust/models") if not x.endswith(".h")]
    available_trust_chooses = [x for x in os.listdir("wsn/common/trust/choose") if not x.endswith(".h")]
    available_adversary = [x[:-len(".c")] for x in os.listdir("wsn/adversary/attacks") if x.endswith(".c")]
    available_applications = [x for x in os.listdir("wsn/applications") if os.path.isdir(os.path.join("wsn/applications", x))]

    parser = argparse.ArgumentParser(description='Setup')
    parser.add_argument('trust_model', type=str, choices=available_trust_models, help='The trust model to use')
    parser.add_argument('trust_choose', type=str, choices=available_trust_chooses, help='The trust choose to use')
    parser.add_argument('--applications', nargs="+", type=str, choices=available_applications, help='The applications to build for')
    parser.add_argument('--with-pcap', action='store_true', help='Enable capturing and outputting pcap dumps from the nodes')
    parser.add_argument('--with-adversary', nargs="*", type=str, choices=available_adversary, default=None, help='Enable building an adversary')
    parser.add_argument('--defines', nargs="*", action=DefinesAction, metavar="define-name define-value", default={},
                        help='Defines to pass to compilation')
    args = parser.parse_args()

    setup = Setup(args.trust_model, args.trust_choose, args.applications, args.with_pcap, args.with_adversary, args.defines)
    setup.run()
