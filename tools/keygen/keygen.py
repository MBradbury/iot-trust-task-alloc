from __future__ import annotations

from textwrap import wrap
import pathlib
from more_itertools import chunked

from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

def derive_private_key(deterministic_string: Optional[str]=None):
    if deterministic_string is None:
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        # Byteorder and signed here doesn't matter, is just needed to convert into an int
        private_value = int.from_bytes(sha256(deterministic_string.encode("utf-8")).digest(), byteorder="little", signed=False)

        return ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

def save_key(pk, name: str, keystore_dir: str):
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

def generate_and_save_key(keystore_dir: str="keystore", deterministic_string: Optional[str]=None):
    print(f"Generating key using {deterministic_string}")
    private_key = derive_private_key(deterministic_string)

    print(f"Saving key to {keystore_dir}")
    save_key(private_key, deterministic_string, keystore_dir)

    return private_key
