#!/usr/bin/env python3

import logging
import time

from config import serial_sep
import client_common

NAME = "envmon"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"app-{NAME}")
logger.setLevel(logging.DEBUG)

def _task_runner(task):
    (src, dt, payload) = task

    (node_time, temp, vdd3) = payload

    start_timer = time.perf_counter()

    logger.info(f"Received message at {dt} from {src} <time={node_time}, temp={temp}, vdd3={vdd3}>")

    end_timer = time.perf_counter()
    duration = end_timer - start_timer

    return (src, None, duration)

class MonitoringClient(client_common.Client):
    def __init__(self):
        super().__init__(NAME, task_runner=_task_runner, max_workers=1)

    async def _send_result(self, dest, message_response):
        # TODO: do something here
        pass

if __name__ == "__main__":
    client = MonitoringClient()

    client_common.main(NAME, client)
