#!/usr/bin/env python3

import cbor2
from runstats import Statistics

import asyncio
import logging
from datetime import datetime
import ipaddress
import time
from concurrent.futures import ProcessPoolExecutor
import math
import base64
import hashlib

from config import application_edge_marker, serial_sep
import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-challenge-response")
logger.setLevel(logging.DEBUG)

class ChallengeResponseClient(client_common.Client):

    task_resp_prefix = f"app{serial_sep}resp{serial_sep}"
    task_stats_prefix = f"app{serial_sep}stats{serial_sep}"

    def __init__(self):
        super().__init__("cr")
        self.stats = Statistics()
        self.executor = ProcessPoolExecutor(max_workers=1)

    async def stop(self):
        self.executor.shutdown()

        await super().stop()

    async def receive(self, message: str):
        try:
            dt, src, payload_len, payload = message.split(serial_sep, 3)

            dt = datetime.fromisoformat(dt)
            src = ipaddress.IPv6Address(src)
            payload_len = int(payload_len)
            payload = cbor2.loads(bytes.fromhex(payload))

            (difficulty, data, max_duration) = payload

            logger.debug(f"Received challenge at {dt} from {src} <"
                f"difficulty={difficulty}, "
                f"data={data}>")

        except Exception as ex:
            logger.error(f"Failed to parse message '{message}' with {ex}")
            return

        task = (src, difficulty, data, max_duration)

        loop = asyncio.get_running_loop()
        task_result = await loop.run_in_executor(self.executor, _task_runner, task)

        (dest, prefix, duration) = task_result
        
        # Update the average time taken to perform jobs
        # TODO: should this be EWMA
        self.stats.push(duration)

        await self._send_result(dest, (prefix, int(math.ceil(duration))))

    async def _send_result(self, dest, message_response):
        # Push the updated stats to the node, this is used to inform the expected time to perform the task
        await self._write_task_stats()
        await self._write_task_result(dest, message_response)

    async def _write_task_stats(self):
        await self._write_to_application(f"{self.task_stats_prefix}{self._stats_string()}")
        await self._receive_ack()

    async def _write_task_result(self, dest, message_response):
        encoded = base64.b64encode(cbor2.encoder.dumps(message_response)).decode("utf-8")

        await self._write_to_application(f"{self.task_resp_prefix}{dest}{serial_sep}{encoded}")
        await self._receive_ack()

    async def _receive_ack(self):
        write_ack = (await self.reader.readline()).decode("utf-8")
        if not write_ack.endswith(f"{serial_sep}ack\n"):
            logger.error(f"Ack string was not in expected format {write_ack!r}")

    def _stats_string(self):
        try:
            variance = int(math.ceil(self.stats.variance()))
        except ZeroDivisionError:
            variance = 0

        mean = int(math.ceil(self.stats.mean()))
        maximum = int(math.ceil(self.stats.maximum()))
        minimum = int(math.ceil(self.stats.minimum()))

        data = [mean, maximum, minimum, variance]

        return base64.b64encode(cbor2.dumps(data)).decode("utf-8")

def _task_runner(task):
    (src, difficulty, data, max_duration) = task

    start_timer = time.perf_counter()

    # find a suitable prefix such that the first `difficulty` bytes of the hash are zero
    prefix_int = 0

    timeout = False

    while True:
        # Give up
        if time.perf_counter() - start_timer >= max_duration:
            timeout = True
            break

        prefix = prefix_int.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

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
        logger.warning(f"Job {task} took {duration} seconds and failed to find prefix")
    else:
        logger.info(f"Job {task} took {duration} seconds and found prefix {prefix}")

    return (src, prefix if not timeout else b"", duration)

if __name__ == "__main__":
    client = ChallengeResponseClient()

    client_common.main("cr", client)
