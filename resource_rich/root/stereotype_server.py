import logging
import asyncio
import ipaddress
import os
from enum import IntEnum
from dataclasses import dataclass

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

import cbor2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stereotype-server")
logger.setLevel(logging.DEBUG)

class TrustModel(IntEnum):
    No = 0
    Basic = 1
    Continuous = 2
    ChallengeResponse = 3

    def to_cbor(self):
        return int(self)

class DeviceClass(IntEnum):
    RASPBERRY_PI = 1
    PHONE = 2
    LAPTOP = 3
    DESKTOP = 4
    SERVER = 5

    def to_cbor(self):
        return int(self)

@dataclass(frozen=True)
class StereotypeTags:
    device_class: DeviceClass

    def __post_init__(self):
        super().__setattr__("device_class", DeviceClass(self.device_class))

    def to_cbor(self):
        return [self.device_class.to_cbor()]

@dataclass(frozen=True)
class StereotypeRequest:
    model: TrustModel
    addr: ipaddress.IPv6Address
    tags: StereotypeTags

    def __post_init__(self):
        super().__setattr__("model", TrustModel(self.model))
        super().__setattr__("addr", ipaddress.ip_address(self.addr))
        super().__setattr__("tags", StereotypeTags(*self.tags))

    def to_cbor(self):
        return [self.model.to_cbor(), self.addr, self.tags.to_cbor()]

class StereotypeServer(resource.Resource):
    async def render_get(self, request):
        """Return stereotype information for the requested Edge server"""
        if request.opt.content_format != media_types_rev['application/cbor']:
            raise error.UnsupportedContentFormat()

        payload = cbor2.loads(request.payload)
        payload = StereotypeRequest(*payload)

        # TODO: include verification that the edge node has included correct tags

        if payload.model == TrustModel.No:
            result = self._no_trust_model(payload)

        elif payload.model == TrustModel.Basic:
            result = self._basic_trust_model(payload)

        elif payload.model == TrustModel.Continuous:
            result = self._continuous_trust_model(payload)

        elif payload.model == TrustModel.ChallengeResponse:
            result = self._challenge_response_trust_model(payload)

        else:
            raise error.BadRequest(f"Unknown trust model {payload.model}")

        result_payload = cbor2.dumps([
            payload.model.to_cbor(),
            ipaddress.v6_int_to_packed(int(payload.addr)),
            payload.tags.to_cbor(),
            result
        ])

        return aiocoap.Message(payload=result_payload, code=codes.CONTENT, content_format=media_types_rev['application/cbor'])

    def _no_trust_model(self, payload: StereotypeRequest):
        # No trust information
        return None

    def _basic_trust_model(self, payload: StereotypeRequest):
        # All classes of nodes are expected to be good at acknowledging tasks
        task_submission = [10, 1]

        # More capable devices are expected to be better a delivering a result
        if payload.tags.device_class == DeviceClass.RASPBERRY_PI:
            task_result = [4, 1]

        elif payload.tags.device_class == DeviceClass.PHONE:
            task_result = [6, 1]

        elif payload.tags.device_class == DeviceClass.LAPTOP:
            task_result = [8, 1]

        elif payload.tags.device_class == DeviceClass.SERVER:
            task_result = [10, 1]

        else:
            raise error.BadRequest(f"Unknown device class {payload.tags.device_class}")
        
        return [task_submission, task_result]

    def _continuous_trust_model(self, payload: StereotypeRequest):
        raise error.NotImplemented()

    def _challenge_response_trust_model(self, payload: StereotypeRequest):
        # epoch number is 0 and bad is False
        return [0, False]



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
