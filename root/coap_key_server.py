#!/usr/bin/env python3

import logging
import asyncio
import ipaddress
import os

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("coap-key-server")
logger.setLevel(logging.DEBUG)

class InvalidAddressRequest(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Invalid IP Address requested"

class UnknownAddressRequest(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Unknown IP Address requested"

class COAPKeyServer(resource.Resource):
    def __init__(self, key_dir):
        super().__init__()
        self.key_dir = key_dir
        self.keystore = {}

        # Load the server's public/private key
        self.privkey = self._load_privkey(os.path.join(key_dir, "private.pem"))

    def _load_privkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def _load_pubkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def _load_key(self, addr):
        logger.info(f"Loading key for {addr}")

        file = str(addr).replace(":", "_") + "-public.pem"

        key = self._load_pubkey(os.path.join(self.key_dir, file))

        self.keystore[addr] = key

        return key

    def _key_to_message(self, addr, key):
        # 16 bytes for the IP address who the key belongs to
        addr_bytes = int(addr).to_bytes(16, byteorder='big')

        # Raw Public Key (64 bytes_)
        public_numbers = key.public_numbers()
        x = public_numbers.x.to_bytes(32, byteorder='big')
        y = public_numbers.y.to_bytes(32, byteorder='big')

        payload = addr_bytes + x + y

        # Raw signature (64 bytes)
        sig = self.privkey.sign(payload, ec.ECDSA(hashes.SHA256()))

        (r, s) = decode_dss_signature(sig)

        r = r.to_bytes(32, byteorder='big')
        s = s.to_bytes(32, byteorder='big')

        payload += (r + s)

        return aiocoap.Message(payload=payload, content_format=media_types_rev['application/octet-stream'])

    async def render_get(self, request):
        """An MQTT Subscribe request"""
        try:
        	request_address = ipaddress.IPv6Address(request.payload.decode("utf-8"))
        except ValueError:
            # Try parsing as bytes
            if len(request.payload) == 16:
                try:
                    request_address = ipaddress.IPv6Address(request.payload)
                except ValueError:
                    raise InvalidAddressRequest()
            else:
                raise InvalidAddressRequest()

        logger.info(f"Received request for {request_address} from {request.remote}")

        # Convert to global address, if request is for link-local
        if str(request_address).startswith("fe80"):
            global_request_address = ipaddress.IPv6Address("fd00" + str(request_address)[4:])

            logger.info(f"Request is for link-local address {request_address}, converting to global address {global_request_address}")

            request_address = global_request_address

        key = self.keystore.get(request_address, None)
        if key is None:
            try:
                key = self._load_key(request_address)
            except FileNotFoundError:
                raise UnknownAddressRequest()
        else:
            logger.info(f"Using cached public key for {request_address} as response")

        return self._key_to_message(request_address, key)


def main(key_dir, coap_target_port):
    logger.info("Starting coap key server")

    loop = asyncio.get_event_loop()

    coap_site = resource.Site()
    coap_site.add_resource(['.well-known', 'core'],
        resource.WKCResource(coap_site.get_resources_as_linkheader, impl_info=None))
    coap_site.add_resource(['key'], COAPKeyServer(key_dir))

    try:
        loop.create_task(aiocoap.Context.create_server_context(coap_site))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the mqtt-coap bridge.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='CoAP Key Server')
    parser.add_argument('-p', '--coap-target-port', type=int, default=5683, help='The target port for CoAP messages to be POSTed to')
    parser.add_argument('-k', '--key-directory', type=str, required=True, help='The location of serialised database')

    args = parser.parse_args()

    main(key_dir=args.key_dir, coap_target_port=args.coap_target_port)
