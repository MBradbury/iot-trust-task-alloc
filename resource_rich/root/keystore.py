import logging
import os
import ipaddress

from common.certificate import SignedCertificate

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("keystore")
logger.setLevel(logging.DEBUG)

class Keystore:
    def __init__(self, key_dir):
        self.key_dir = key_dir

        self.keystore = {}
        self.certstore = {}

        # Load the server's public/private key
        self.privkey = self._load_privkey(os.path.join(key_dir, "private.pem"))

    def list_addresses(self):
        with os.scandir(self.key_dir) as it:
            for entry in it:
                if entry.name.endswith("-public.pem"):
                    prefix = entry.name[:-len("-public.pem")].replace("_", ":")

                    yield ipaddress.ip_address(prefix)

    def _load_privkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def _load_pubkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def get_pubkey(self, request_address):
        key = self.keystore.get(request_address, None)
        if key is None:
            file = str(request_address).replace(":", "_") + "-public.pem"

            logger.info(f"Loading key for {request_address} from file {file}")

            self.keystore[request_address] = key = self._load_pubkey(os.path.join(self.key_dir, file))

        else:
            logger.info(f"Using cached public key for {request_address} as response")

        return key

    def _load_cert(self, path):
        with open(path, 'rb') as f:
            return f.read()

    def get_cert(self, request_address):
        cert = self.certstore.get(request_address, None)
        if cert is None:
            file = str(request_address).replace(":", "_") + "-cert.iot-trust-cert"

            logger.info(f"Loading cert for {request_address} from file {file}")

            self.certstore[request_address] = cert = self._load_cert(os.path.join(self.key_dir, file))

        else:
            logger.info(f"Using cached public cert for {request_address} as response")

        return cert

    def oscore_ident(self, request_address) -> bytes:
        cert = SignedCertificate.decode(self.get_cert(request_address))

        # OSCORE IDs are the last 6 bytes of the EUI-64
        return cert.subject[-6:]

    def shared_secret(self, request_address) -> bytes:
        their_pubkey = self.get_pubkey(request_address)
        shared_key = self.privkey.exchange(ec.ECDH(), their_pubkey)

        return shared_key
