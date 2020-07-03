#!/usr/bin/env python3

import cbor2
from pyroutelib3 import Router
from runstats import Statistics

import asyncio
import logging
from datetime import datetime
import ipaddress
import struct
import time
from concurrent.futures import ProcessPoolExecutor
import math
import base64

from config import application_edge_marker, serial_sep
import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-routing")
logger.setLevel(logging.DEBUG)

# From: https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class RoutingClient(client_common.Client):

    task_resp1_prefix = f"app{serial_sep}resp1{serial_sep}"
    task_resp2_prefix = f"app{serial_sep}resp2{serial_sep}"
    task_stats_prefix = f"app{serial_sep}stats{serial_sep}"

    def __init__(self):
        super().__init__("routing")
        self.stats = Statistics()

    async def receive(self, message: str):
        try:
            dt, src, payload_len, payload = message.split(serial_sep, 3)

            dt = datetime.fromisoformat(dt)
            src = ipaddress.IPv6Address(src)
            payload_len = int(payload_len)
            payload = cbor2.loads(bytes.fromhex(payload))

            (time, routing_source, routing_destination) = payload

            logger.debug(f"Received message at {dt} from {src} <time={time}, routing_source={routing_source}, routing_destination={routing_destination}>")

        except:
            logger.error(f"Failed to parse message '{message}'")
            return

        task = (src, routing_source, routing_destination)

        loop = asyncio.get_running_loop()
        with ProcessPoolExecutor() as pool:
            task_result = await loop.run_in_executor(pool, _task_runner, task)

        (dest, message_response, duration) = task_result
        
        # Update the average time taken to perform jobs
        # TODO: should this be EWMA
        self.stats.push(duration)

        await self._send_result(dest, message_response)

    async def _send_result(self, dest, message_response):
        status, route = message_response

        # Push the updated stats to the node, this is used to inform the expected time to perform the task
        await self._write_task_stats()

        # 2 limitations:
        # (i) serial buffer is limited to 128 characters
        # (ii) coap message is similarly limited (although not as much as the serial buffer)
        # So we need to chunk the route we have received, send over serial and wait for confirmation of
        # when the message has been successfully received

        if status == 0:
            # Find the maximum number of messages we will need to send
            prefix_len = len(f"{self.message_prefix}{self.task_resp2_prefix}")
            suffix_len = 1 # newline character

            # How much space there is left to include a message
            available = self.max_serial_len - prefix_len - suffix_len

            # Take away initial array marker
            available = available - 2

            # Take away counter (assume XX/XX|)
            available = available - 6

            # 1 byte for array marker (assuming small chunks)
            # 1 array marker and pair of lat,lon 4 byte floats 
            per_item_cost = 1 + 4*2
            per_item_cost_b64 = math.ceil(per_item_cost / 6) * 8

            elements = int(math.floor(available / per_item_cost_b64))

            logger.debug(f"Sending routes chunk with {elements} items each [prefix_len={prefix_len}, available={available}, per_item_cost={per_item_cost}, per_item_cost_b64={per_item_cost_b64}]")

            route_chunks = list(chunks(route, elements))

            await self._write_task_result_result(dest, status, len(route_chunks))

            for i, route_chunk in enumerate(route_chunks, start=1):
                await self._write_task_result_chunk(i, len(route_chunks), route_chunk)

        else:
            await self._write_task_result_result(dest, status, 0)

    async def _write_task_stats(self):
        await self._write_to_application(f"{self.task_stats_prefix}{self._stats_string()}")
        await self._receive_ack()

    async def _write_task_result_result(self, dest, status, n):
        await self._write_to_application(f"{self.task_resp1_prefix}{dest}{serial_sep}{n}{serial_sep}{status}")
        await self._receive_ack()

    async def _write_task_result_chunk(self, i, n, route_chunk):
        # Need canonical to fit floats into smallest space possible
        encoded = base64.b64encode(cbor2.encoder.dumps(route_chunk, canonical=True)).decode("utf-8")

        # Send task response back to edge sensor node
        await self._write_to_application(f"{self.task_resp2_prefix}{i}/{n}{serial_sep}{encoded}")
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

def _format_route(route):
    # By default using canonical=True will try to format floats
    # in the smalklest possible representation.
    # As we only plan on using 4 byte floats on the sensor nodes,
    # we can save space by forcing the coordinates to fit in a 4 byte float.

    def truncate_float(x):
        return struct.unpack("f", struct.pack("f", x))[0]

    return [
        (truncate_float(lat), truncate_float(lon))
        for (lat, lon)
        in route
    ]

def _task_runner(task):
    (src, routing_source, routing_destination) = task

    start_timer = time.perf_counter()

    router = Router("car")

    start = router.findNode(routing_source[0], routing_source[1])
    end = router.findNode(routing_destination[0], routing_destination[1])

    status, route = router.doRoute(start, end)
    if status == "success":
        route_coords = [router.nodeLatLon(x) for x in route]
        encoded_route = (0, _format_route(route_coords))
    elif status == "no_route":
        encoded_route = (1, None)
    elif status == "gave_up":
        encoded_route = (2, None)
    else:
        logger.error(f"Unknown result '{status}'")
        encoded_route = (3, None)

    end_timer = time.perf_counter()

    encoded_route_len = 0 if encoded_route[1] is None else len(encoded_route[1])
    logger.debug(f"Job {task} took {end_timer - start_timer} seconds with status {status} route length = {encoded_route_len}")

    return (src, encoded_route, end_timer - start_timer)

if __name__ == "__main__":
    client = RoutingClient()

    client_common.main("routing", client)
