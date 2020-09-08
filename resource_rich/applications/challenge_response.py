#!/usr/bin/env python3

import cbor2

import logging
import time
import math
import base64
import hashlib

from config import serial_sep
import client_common

NAME = "cr"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"app-{NAME}")
logger.setLevel(logging.DEBUG)

def _task_runner(task):
    (src, dt, (difficulty, data, max_duration)) = task

    start_timer = time.perf_counter()

    # find a suitable prefix such that the first `difficulty` bytes of the hash are zero
    prefix_int = 0

    timeout = False

    while True:
        # Give up
        if time.perf_counter() - start_timer >= max_duration:
            timeout = True
            break

        prefix = prefix_int.to_bytes((prefix_int.bit_length() + 7) // 8, byteorder='big')

        m = hashlib.sha256()
        m.update(prefix)
        m.update(data)
        digest = m.digest()

        # Have we found a suitable prefix
        if all(x == 0 for x in digest[0:difficulty]):
            break
        else:
            prefix_int += 1

    end_timer = time.perf_counter()
    duration = end_timer - start_timer

    if timeout:
        logger.warning(f"Job {task} took {duration} seconds and {prefix_int} iterations and failed to find prefix")
    else:
        logger.info(f"Job {task} took {duration} seconds and {prefix_int} iterations and found prefix {prefix}")

    response = (prefix if not timeout else b"", int(math.ceil(duration)))

    return (src, response, duration)

class ChallengeResponseClient(client_common.Client):

    task_resp_prefix = f"app{serial_sep}resp{serial_sep}"

    def __init__(self):
        super().__init__(NAME, task_runner=_task_runner, max_workers=2)

    async def _send_result(self, dest, message_response):
        # Push the updated stats to the node, this is used to inform the expected time to perform the task
        await self._write_task_stats()
        await self._write_task_result(dest, message_response)

    async def _write_task_result(self, dest, message_response):
        encoded = base64.b64encode(cbor2.encoder.dumps(message_response)).decode("utf-8")

        await self._write_to_application(f"{self.task_resp_prefix}{dest}{serial_sep}{encoded}")
        await self._receive_ack()

if __name__ == "__main__":
    client = ChallengeResponseClient()

    client_common.main(NAME, client)
