#!/usr/bin/env python3

import logging
from datetime import datetime
import ipaddress

import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-monitoring")
logger.setLevel(logging.DEBUG)

serial_sep = "|"

class MonitoringClient(client_common.Client):
    def __init__(self):
        super().__init__("envmon")

    async def receive(self, message: str):
        logger.info(f"Received message '{message}'")

        dt, src, payload_len, payload = message.split(serial_sep, 3)

        dt = datetime.fromisoformat(dt)
        src = ipaddress.IPv6Address(src)
        payload_len = int(payload_len)

        # TODO: do something with this message

if __name__ == "__main__":
    client = MonitoringClient()

    client_common.main("monitoring", client)
