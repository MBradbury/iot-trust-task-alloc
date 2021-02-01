#!/usr/bin/env python3

"""
This document outputs the equivalent of the following, but also in a format that can be used in C files.
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```
"""

from tools.keygen.keygen import generate_and_save_key, derive_private_key
from tools.keygen.contiking_format import contiking_format_our_privkey, contiking_format_certificate
from tools.keygen.util import ip_to_eui64

from common.certificate import TBSCertificate
from common.stereotype_tags import StereotypeTags, DeviceClass

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='ECC Keygen')
    parser.add_argument('-d', '--deterministic', type=str, default=None, help='The deterministic string to use.')
    parser.add_argument('-r', '--root', type=str, default=None, help='The deterministic root string to use.')
    parser.add_argument('-k', '--keystore-dir', type=str, default="keystore", help='The location to store the output files.')

    parser.add_argument('-s', '--stereo-device-class',
        type=DeviceClass.from_string, choices=list(DeviceClass), default=DeviceClass.RASPBERRY_PI, help='The device class.')

    args = parser.parse_args()

    private_key = generate_and_save_key(args.keystore_dir, args.deterministic)
    root_private_key = derive_private_key(args.root)

    print(contiking_format_our_privkey(private_key, args.deterministic))

    tags = StereotypeTags(
        device_class=args.stereo_device_class
    )

    tbscert = TBSCertificate(
        serial_number=0,
        issuer=ip_to_eui64(args.root),
        validity_from=0,
        validity_to=None,
        subject=ip_to_eui64(args.deterministic),
        stereotype_tags=tags,
        public_key=private_key.public_key(),
    )

    cert = tbscert.build(root_private_key)
    print(cert)

    enc_cert = cert.encode()
    print(enc_cert, len(enc_cert))

    print(contiking_format_certificate(cert, "our_cert"))
