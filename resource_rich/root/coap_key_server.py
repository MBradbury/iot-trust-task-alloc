#!/usr/bin/env python3

import logging
import asyncio
import ipaddress

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .keystore import Keystore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("coap-key-server")
logger.setLevel(logging.DEBUG)

class InvalidAddressRequest(error.BadRequest):
    message = "Error: Invalid IP Address requested"

class UnknownAddressRequest(error.BadRequest):
    message = "Error: Unknown IP Address requested"

class InvalidSignatureRequest(error.BadRequest):
    message = "Error: Invalid signature requested"

# This is the curve used by the sensor nodes to sign and verify messages
curve = ec.SECP256R1

# key_size is in bits. Convert to bytes and round up
curve_byte_len = (curve.key_size + 7) // 8

ipv6_byte_len = 16
sig_endianness = "big"

class COAPKeyServer(resource.Resource):
    def __init__(self, keystore: Keystore):
        super().__init__()
        self.keystore = keystore

    def _cert_to_message(self, addr, key):
        payload = self.sign_message(key)

        return aiocoap.Message(payload=payload, content_format=media_types_rev['application/octet-stream'])

    async def render_get(self, request):
        """An MQTT Subscribe request"""

        try:
            if request.opt.content_format == media_types_rev['text/plain;charset=utf-8']:
                request_address = ipaddress.IPv6Address(request.payload.decode("utf-8"))

            elif request.opt.content_format == media_types_rev['application/octet-stream']:
                request_address = ipaddress.IPv6Address(request.payload[0:ipv6_byte_len])

                if len(request.payload) == ipv6_byte_len + curve_byte_len*2:
                    self.verify_request(request)
            else:
                raise error.UnsupportedContentFormat()

        except InvalidSignature:
            raise InvalidSignatureRequest()

        except (ValueError, UnicodeDecodeError):
            raise InvalidAddressRequest()

        logger.info(f"Received request for {request_address} from {request.remote}")

        # Convert to global address, if request is for link-local
        if str(request_address).startswith("fe80"):
            global_request_address = ipaddress.IPv6Address("fd00" + str(request_address)[4:])

            logger.info(f"Request is for link-local address {request_address}, converting to global address {global_request_address}")

            request_address = global_request_address

        try:
            cert = self.keystore.get_cert(request_address)
        except FileNotFoundError:
            raise UnknownAddressRequest()

        return self._cert_to_message(request_address, cert)


    def verify_request(self, request):
        remote_addr = ipaddress.IPv6Address(request.remote.sockaddr[0])
        pubkey = self.keystore.get_pubkey(remote_addr)

        payload = request.payload[0:-curve_byte_len*2]
        payload_len = len(payload)

        r = request.payload[payload_len               :payload_len+curve_byte_len  ]
        s = request.payload[payload_len+curve_byte_len:payload_len+curve_byte_len*2]

        r = int.from_bytes(r, byteorder=sig_endianness)
        s = int.from_bytes(s, byteorder=sig_endianness)

        sig = utils.encode_dss_signature(r, s)

        pubkey.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        

    def sign_message(self, payload):
        # Raw signature (64 bytes)
        sig = self.keystore.privkey.sign(payload, ec.ECDSA(hashes.SHA256()))

        (r, s) = utils.decode_dss_signature(sig)

        r = r.to_bytes(curve_byte_len, byteorder=sig_endianness)
        s = s.to_bytes(curve_byte_len, byteorder=sig_endianness)

        return payload + r + s


def main(key_dir, coap_target_port):
    logger.info("Starting coap key server")

    loop = asyncio.get_event_loop()

    keystore = Keystore(key_dir)

    coap_site = resource.Site()
    coap_site.add_resource(['.well-known', 'core'],
        resource.WKCResource(coap_site.get_resources_as_linkheader, impl_info=None))
    coap_site.add_resource(['key'], COAPKeyServer(keystore))

    try:
        loop.create_task(aiocoap.Context.create_server_context(coap_site))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the coap key server.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='CoAP Key Server')
    parser.add_argument('-p', '--coap-target-port', type=int, default=5683, help='The target port for CoAP messages to be POSTed to')
    parser.add_argument('-k', '--key-directory', type=str, required=True, help='The location of serialised database')

    args = parser.parse_args()

    main(key_dir=args.key_dir, coap_target_port=args.coap_target_port)
