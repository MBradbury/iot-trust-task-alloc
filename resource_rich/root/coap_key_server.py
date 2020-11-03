#!/usr/bin/env python3

import logging
import asyncio
import ipaddress

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

import cbor2

from .keystore import Keystore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("coap-key-server")
logger.setLevel(logging.DEBUG)

class InvalidAddressRequest(error.BadRequest):
    message = "Error: Invalid IP Address requested"

class UnknownAddressRequest(error.BadRequest):
    message = "Error: Unknown IP Address requested"

ipv6_byte_len = 16

class COAPKeyServer(resource.Resource):
    def __init__(self, keystore: Keystore):
        super().__init__()
        self.keystore = keystore

    async def render_get(self, request):
        """An MQTT Subscribe request"""

        try:
            if request.opt.content_format == media_types_rev['text/plain;charset=utf-8']:
                request_address = ipaddress.IPv6Address(request.payload.decode("utf-8"))

            elif request.opt.content_format == media_types_rev['application/octet-stream']:
                request_address = ipaddress.IPv6Address(request.payload[0:ipv6_byte_len])

            elif request.opt.content_format == media_types_rev['application/cbor']:
                request_address = ipaddress.IPv6Address(cbor2.loads(request.payload))

            else:
                raise error.UnsupportedContentFormat()

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

        return aiocoap.Message(payload=cert, content_format=media_types_rev['application/cbor'])


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
