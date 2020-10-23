from dataclasses import dataclass
import cbor2
from typing import Optional
import numpy as np

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from common.stereotype_tags import StereotypeTags

@dataclass(init=False)
class TBSCertificate:
    serial_number: int
    issuer: bytes
    validity_from: int
    validity_to: int
    subject: bytes
    stereotype_tags: StereotypeTags
    public_key: bytes

    def __init__(self, serial_number: int, issuer: bytes, validity_from: int, validity_to: Optional[int],
                 subject: bytes, stereotype_tags: StereotypeTags, public_key):
        self.serial_number = serial_number
        self.issuer = issuer
        self.validity_from = validity_from
        self.validity_to = validity_to if validity_to is not None else np.iinfo(np.uint32).max
        self.subject = subject
        self.stereotype_tags = stereotype_tags

        if isinstance(public_key, bytes):
            if len(public_key) != 64:
                raise ValueError("public_key must be 64 bytes")

            self.public_key = public_key
        else:
            public_numbers = public_key.public_numbers()
            self.public_key = public_numbers.x.to_bytes(32, 'big') + public_numbers.y.to_bytes(32, 'big')

    def encode(self):
        tbs_certificate = [
            self.serial_number,
            self.issuer,
            [self.validity_from, self.validity_to],
            self.subject,
            self.stereotype_tags.encode(),
            self.public_key,
        ]

        return cbor2.dumps(tbs_certificate)

    def build(self, signer_key):
        sig = signer_key.sign(self.encode(), ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(sig)

        sig_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

        return SignedCertificate(
            serial_number=self.serial_number,
            issuer=self.issuer,
            validity_from=self.validity_from,
            validity_to=self.validity_to,
            subject=self.subject,
            stereotype_tags=self.stereotype_tags,
            public_key=self.public_key,
            signature=sig_bytes,
        )

@dataclass(init=False)
class SignedCertificate:
    serial_number: int
    issuer: bytes
    validity_from: int
    validity_to: int
    subject: bytes
    stereotype_tags: StereotypeTags
    public_key: bytes
    signature: bytes

    def __init__(self, serial_number: int, issuer: bytes, validity_from: int, validity_to: Optional[int],
                 subject: bytes, stereotype_tags: StereotypeTags, public_key, signature: bytes):
        self.serial_number = serial_number
        self.issuer = issuer
        self.validity_from = validity_from
        self.validity_to = validity_to if validity_to is not None else np.iinfo(np.uint32).max
        self.subject = subject
        self.stereotype_tags = stereotype_tags

        if isinstance(public_key, bytes):
            if len(public_key) != 64:
                raise ValueError("public_key must be 64 bytes")

            self.public_key = public_key
        else:
            public_numbers = public_key.public_numbers()
            self.public_key = public_numbers.x.to_bytes(32, 'big') + public_numbers.y.to_bytes(32, 'big')

        self.signature = signature

    def encode(self):
        certificate = [
            [
                self.serial_number,
                self.issuer,
                [self.validity_from, self.validity_to],
                self.subject,
                self.stereotype_tags.encode(),
                self.public_key,
            ],
            self.signature,
        ]

        return cbor2.dumps(certificate)

    @staticmethod
    def decode(data: bytes):
        loaded = cbor2.loads(data)

        return SignedCertificate(
            serial_number=loaded[0][0],
            issuer=loaded[0][1],
            validity_from=loaded[0][2][0],
            validity_to=loaded[0][2][1],
            subject=loaded[0][3],
            stereotype_tags=StereotypeTags.decode(loaded[0][4]),
            public_key=loaded[0][5],
            signature=loaded[1],
        )
