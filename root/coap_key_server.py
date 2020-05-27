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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("coap-key-server")
logger.setLevel(logging.DEBUG)

class InvalidAddressRequest(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Invalid IP Address requested"

class UnknownAddressRequest(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Unknown IP Address requested"

class InvalidSignatureRequest(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Invalid signature requested"

# This is the curve used by the sensor nodes to sign and verify messages
curve = ec.SECP256R1

# key_size is in bits. Convert to bytes and round up
curve_byte_len = (curve.key_size + 7) // 8

ipv6_byte_len = 16

class COAPKeyServer(resource.Resource):
    def __init__(self, key_dir):
        super().__init__()
        self.key_dir = key_dir
        self.keystore = {}

        # Load the server's public/private key
        self.privkey = self._load_privkey(os.path.join(key_dir, "private.pem"))

        self.sig_endianness = "big"

    def _load_privkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def _load_pubkey(self, path):
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def _load_pubkey_cached(self, request_address):
        key = self.keystore.get(request_address, None)
        if key is None:
            file = str(request_address).replace(":", "_") + "-public.pem"

            logger.info(f"Loading key for {request_address} from file {file}")

            self.keystore[request_address] = key = self._load_pubkey(os.path.join(self.key_dir, file))

        else:
            logger.info(f"Using cached public key for {request_address} as response")

        return key

    def _key_to_message(self, addr, key):
        # 16 bytes for the IP address who the key belongs to
        addr_bytes = int(addr).to_bytes(ipv6_byte_len, byteorder='big')

        # Raw Public Key (64 bytes)
        public_numbers = key.public_numbers()
        x = public_numbers.x.to_bytes(curve_byte_len, byteorder=self.sig_endianness)
        y = public_numbers.y.to_bytes(curve_byte_len, byteorder=self.sig_endianness)

        payload = addr_bytes + x + y

        payload = self.sign_message(payload)

        return aiocoap.Message(payload=payload, content_format=media_types_rev['application/octet-stream'])

    async def render_get(self, request):
        """An MQTT Subscribe request"""
        try:
        	request_address = ipaddress.IPv6Address(request.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            # Try parsing as bytes
            if len(request.payload) == ipv6_byte_len:
                try:
                    request_address = ipaddress.IPv6Address(request.payload)
                except ValueError:
                    raise InvalidAddressRequest()

            # Try parsing as bytes with a signature
            elif len(request.payload) == ipv6_byte_len + curve_byte_len*2:
                payload = request.payload[0:ipv6_byte_len]

                try:
                    request_address = ipaddress.IPv6Address(payload)
                except ValueError:
                    raise InvalidAddressRequest()

                try:
                    self.verify_request(request)
                except InvalidSignature:
                    raise InvalidSignatureRequest()

            else:
                raise InvalidAddressRequest()

        logger.info(f"Received request for {request_address} from {request.remote}")

        # Convert to global address, if request is for link-local
        if str(request_address).startswith("fe80"):
            global_request_address = ipaddress.IPv6Address("fd00" + str(request_address)[4:])

            logger.info(f"Request is for link-local address {request_address}, converting to global address {global_request_address}")

            request_address = global_request_address

        try:
            key = self._load_pubkey_cached(request_address)
        except FileNotFoundError:
            raise UnknownAddressRequest()

        return self._key_to_message(request_address, key)


    def verify_request(self, request):
        remote_addr = ipaddress.IPv6Address(request.remote.sockaddr[0])
        pubkey = self._load_pubkey_cached(remote_addr)

        payload = request.payload[0:-curve_byte_len*2]
        payload_len = len(payload)

        r = request.payload[payload_len               :payload_len+curve_byte_len  ]
        s = request.payload[payload_len+curve_byte_len:payload_len+curve_byte_len*2]

        r = int.from_bytes(r, byteorder=self.sig_endianness)
        s = int.from_bytes(s, byteorder=self.sig_endianness)

        sig = utils.encode_dss_signature(r, s)

        pubkey.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        

    def sign_message(self, payload):
        # Raw signature (64 bytes)
        sig = self.privkey.sign(payload, ec.ECDSA(hashes.SHA256()))

        (r, s) = utils.decode_dss_signature(sig)

        r = r.to_bytes(curve_byte_len, byteorder=self.sig_endianness)
        s = s.to_bytes(curve_byte_len, byteorder=self.sig_endianness)

        return payload + r + s


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
