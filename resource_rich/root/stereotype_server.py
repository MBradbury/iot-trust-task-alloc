from __future__ import annotations

import logging
import asyncio
import os
from enum import IntEnum
from dataclasses import dataclass

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.numbers import media_types_rev
import aiocoap.resource as resource

import cbor2

from common.stereotype_tags import *
from common.certificate import SignedCertificate
from .keystore import Keystore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stereotype-server")
logger.setLevel(logging.DEBUG)

class TrustModel(IntEnum):
    No = 0
    Basic = 1
    Continuous = 2
    ChallengeResponse = 3

    def encode(self) -> int:
        return int(self)

@dataclass(frozen=True)
class StereotypeRequest:
    model: TrustModel
    tags: StereotypeTags

    @staticmethod
    def decode(payload: bytes) -> StereotypeRequest:
        model, tags = cbor2.loads(payload)

        model = TrustModel(model)
        tags = StereotypeTags(*tags)

        return StereotypeRequest(model, tags)

@dataclass(frozen=True)
class StereotypeResponse:
    model: TrustModel
    tags: StereotypeTags
    result: object

    def encode(self):
        return [
            self.model.encode(),
            self.tags.encode(),
            self.result
        ]

class StereotypeServer(resource.Resource):
    async def render_get(self, request):
        """Return stereotype information for the requested Edge server"""
        if request.opt.content_format != media_types_rev['application/cbor']:
            raise error.UnsupportedContentFormat()

        payload = StereotypeRequest.decode(request.payload)

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

        result = StereotypeResponse(payload.model, payload.tags, result)
        result_payload = cbor2.dumps(result.encode())

        return aiocoap.Message(payload=result_payload, code=codes.CONTENT, content_format=media_types_rev['application/cbor'])

    def _no_trust_model(self, payload: StereotypeRequest):
        # No trust information
        return None

    def _basic_trust_model(self, payload: StereotypeRequest):
        # All classes of nodes are expected to be good at acknowledging tasks
        task_submission = [20, 1]

        # More capable devices are expected to be better a delivering a result
        if payload.tags.device_class == DeviceClass.RASPBERRY_PI:
            task_result = [8, 1]

        elif payload.tags.device_class == DeviceClass.PHONE:
            task_result = [12, 1]

        elif payload.tags.device_class == DeviceClass.LAPTOP:
            task_result = [16, 1]

        elif payload.tags.device_class == DeviceClass.SERVER:
            task_result = [20, 1]

        else:
            raise error.BadRequest(f"Unknown device class {payload.tags.device_class}")
        
        return [task_submission, task_result]

    def _continuous_trust_model(self, payload: StereotypeRequest):
        raise error.NotImplemented()

    def _challenge_response_trust_model(self, payload: StereotypeRequest):
        # epoch number is 0 and bad is False
        return [0, False]



def main(key_dir, coap_target_port):
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

    main(key_dir=args.key_dir, coap_target_port=args.coap_target_port)
