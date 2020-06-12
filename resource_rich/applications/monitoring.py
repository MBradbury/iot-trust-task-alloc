#!/usr/bin/env python3

import logging

import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-monitoring")
logger.setLevel(logging.DEBUG)

class MonitoringClient(client_common.Client):
    def __init__(self):
        super().__init__("envmon")

    async def receive(self, message: str):
        logger.info(f"Received message '{message}'")

        # TODO: do something with this message

if __name__ == "__main__":
    client = MonitoringClient()

    client_common.main("monitoring", [client])
