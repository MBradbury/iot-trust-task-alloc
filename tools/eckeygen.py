#!/usr/bin/env python3

"""
This document outputs the equivalent of the following, but also in a format that can be used in C files.
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```
"""

from tools.keygen.keygen import generate_and_save_key, derive_private_key
from tools.keygen.contiking_format import contiking_format_our_key, contiking_format_our_key_cert, contiking_format_certificate

from tools.keygen.certgen import TBSCertificate

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='ECC Keygen')
    parser.add_argument('-d', '--deterministic', type=str, default=None, help='The deterministic string to use.')
    parser.add_argument('-r', '--root', type=str, default=None, help='The deterministic root string to use.')
    parser.add_argument('-k', '--keystore-dir', type=str, default="keystore", help='The location to store the output files.')

    args = parser.parse_args()

    private_key = generate_and_save_key(args.keystore_dir, args.deterministic)
    root_private_key = derive_private_key(args.root)

    print(contiking_format_our_key(private_key, args.deterministic))

    print(contiking_format_our_key_cert(private_key, root_private_key, args.deterministic, args.root))

    tags = StereotypeTags(
        device_class=DeviceClass.RASPBERRY_PI
    )

    tbscert = TBSCertificate(
        serial_number=0,
        issuer=b"\x00\x00\x00\x00\x00\x00\x00\x01",
        validity_from=0,
        validity_to=None,
        subject=b"\x00\x00\x00\x00\x00\x00\x00\x02",
        stereotype_tags=tags,
        public_key=private_key.public_key(),
    )

    cert = tbscert.build(root_private_key)
    print(cert)

    enc_cert = cert.encode()
    print(enc_cert, len(enc_cert))

    print(contiking_format_certificate(cert, "our_cert"))
