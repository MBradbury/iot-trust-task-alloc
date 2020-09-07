#!/usr/bin/env python3

import cbor2

import logging
from datetime import datetime
import ipaddress

from config import serial_sep
import client_common

NAME = "envmon"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"app-{NAME}")
logger.setLevel(logging.DEBUG)

class MonitoringClient(client_common.Client):
    def __init__(self):
        super().__init__(NAME)

    async def receive(self, message: str):
        try:
            dt, src, payload_len, payload = message.split(serial_sep, 3)

            dt = datetime.fromisoformat(dt)
            src = ipaddress.IPv6Address(src)
            payload_len = int(payload_len)
            payload = cbor2.loads(bytes.fromhex(payload))

            (time, temp, vdd3) = payload

            logger.debug(f"Received message at {dt} from {src} <time={time}, temp={temp}, vdd3={vdd3}>")

        except Exception as ex:
            logger.error(f"Failed to parse message '{message}' with {ex}")
            return

        # TODO: do something with this message

if __name__ == "__main__":
    client = MonitoringClient()

    client_common.main(NAME, client)
