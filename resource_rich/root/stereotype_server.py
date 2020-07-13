import logging
import asyncio
import ipaddress
import os

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

import cbor2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stereotype-server")
logger.setLevel(logging.DEBUG)

class StereotypeServer(resource.Resource):
    async def render_get(self, request):
        """Return stereotype information for the requested Edge server"""
        if request.opt.content_format != media_types_rev['application/cbor']:
            raise error.UnsupportedContentFormat()

        payload = cbor2.loads(request.payload)

        




def main(coap_target_port):
    logger.info("Starting stereotype server")

    loop = asyncio.get_event_loop()

    coap_site = resource.Site()
    coap_site.add_resource(['.well-known', 'core'],
        resource.WKCResource(coap_site.get_resources_as_linkheader, impl_info=None))
    coap_site.add_resource(['stereotype'], StereotypeServer())

    try:
        loop.create_task(aiocoap.Context.create_server_context(coap_site))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the stereotype server.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Stereotype Server')
    parser.add_argument('-p', '--coap-target-port', type=int, default=5683, help='The target port for CoAP messages to be POSTed to')

    args = parser.parse_args()

    main(coap_target_port=args.coap_target_port)
