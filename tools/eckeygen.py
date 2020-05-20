#!/usr/bin/env python3

"""
This document outputs the equivalent of the following, but also in a format that can be used in C files.
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```
"""

from textwrap import wrap
import pathlib

from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# From: https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def save_key(pk, name, keystore_dir):
    """From: https://stackoverflow.com/questions/45146504/python-cryptography-module-save-load-rsa-keys-to-from-file"""

    pathlib.Path(keystore_dir).mkdir(parents=True, exist_ok=True)

    if name is not None:
        prefix = name.replace(":", "_") + "-"
    else:
        prefix = ""

    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{keystore_dir}/{prefix}private.pem", 'wb') as pem_out:
        pem_out.write(pem)


    pem = pk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{keystore_dir}/{prefix}public.pem", 'wb') as pem_out:
        pem_out.write(pem)


def format_individual(number, size, line_group_size=None):
    hex_num = number.to_bytes(32, 'big').hex().upper()

    wrapped = [f"0x{part}" for part in wrap(hex_num, size)]

    if line_group_size is None:
        return ", ".join(wrapped)
    else:
        chunked = list(chunks(wrapped, line_group_size))
        return ",\n                  ".join([", ".join(chunk) for chunk in chunked])

def contiking_format_our_key(private_key, deterministic_string=None):
    public_key_nums = private_key.public_key().public_numbers()
    private_value = private_key.private_numbers().private_value

    private_key_hex_formatted = format_individual(private_value, 2, line_group_size=8)
    public_key_nums_x_formatted = format_individual(public_key_nums.x, 2, line_group_size=8)
    public_key_nums_y_formatted = format_individual(public_key_nums.y, 2, line_group_size=8)

    return f"""const ecdsa_secp256r1_key_t our_key = {{ // {deterministic_string}
    .priv_key = {{ {private_key_hex_formatted} }},
    .pub_key = {{
           .x = {{ {public_key_nums_x_formatted} }},
           .y = {{ {public_key_nums_y_formatted} }} }}
}};"""

def contiking_format_root_key(private_key, deterministic_string=None):
    public_key_nums = private_key.public_key().public_numbers()

    public_key_nums_x_formatted = format_individual(public_key_nums.x, 2, line_group_size=8)
    public_key_nums_y_formatted = format_individual(public_key_nums.y, 2, line_group_size=8)

    return f"""const ecdsa_secp256r1_pubkey_t root_key = {{ // {deterministic_string}
           .x = {{ {public_key_nums_x_formatted} }},
           .y = {{ {public_key_nums_y_formatted} }}
}};"""

def main(deterministic_string, keystore_dir):
    if deterministic_string is None:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        print(f"Generating deterministic key using {deterministic_string}")

        # Byteorder and signed here doesn't matter, is just needed to convert into an int
        private_value = int.from_bytes(sha256(deterministic_string.encode("utf-8")).digest(), byteorder="little", signed=False)

        private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

    save_key(private_key, deterministic_string, keystore_dir)

    return private_key

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='ECC Keygen')
    parser.add_argument('-d', '--deterministic', type=str, default=None, help='The deterministic string to use.')
    parser.add_argument('-k', '--keystore-dir', type=str, default="keystore", help='The location to store the output files.')

    args = parser.parse_args()

    private_key = main(args.deterministic, args.keystore_dir)
    out_format = contiking_format_our_key(private_key, args.deterministic)
    print(out_format)
