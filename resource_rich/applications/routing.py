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

from config import application_edge_marker, serial_sep
import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-routing")
logger.setLevel(logging.DEBUG)

class RoutingClient(client_common.Client):
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
        message_response = message_response.hex()

        # Send task response back to edge sensor node
        await self.write(
            f"{application_edge_marker}{self.name}{serial_sep}app{serial_sep}task-resp{serial_sep}"
            f"{dest}{serial_sep}{message_response}\n")

        # Update the average time taken to perform jobs
        self.stats.push(duration)

        # Push the updated stats to the node, this is used to inform the expected time to perform the task
        # TODO: should this be an EWMA?
        await self.write(
            f"{application_edge_marker}{self.name}{serial_sep}app{serial_sep}task-stats{serial_sep}{self._stats_string()}\n")

    def _stats_string(self):
        try:
            variance = self.stats.mean()
        except ZeroDivisionError:
            variance = 0

        return f"{self.stats.mean()}{serial_sep}{self.stats.maximum()}{serial_sep}{self.stats.minimum()}{serial_sep}{variance}"

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
        route_cbor = _format_route(route_coords)

        logger.debug(f"CBOR response length ({len(route_cbor)}) for route (len={len(route_coords)})")

        encoded_route = cbor2.encoder.dumps((0, route_cbor), canonical=True)
    elif status == "no_route":
        encoded_route = cbor2.encoder.dumps((1, None), canonical=True)
    elif status == "gave_up":
        encoded_route = cbor2.encoder.dumps((2, None), canonical=True)
    else:
        logger.error(f"Unknown result '{status}'")
        encoded_route = cbor2.encoder.dumps((3, None), canonical=True)

    end_timer = time.perf_counter()

    logger.debug(f"Job {task} took {end_timer - start_timer} seconds with status {status}")

    return (src, encoded_route, end_timer - start_timer)

if __name__ == "__main__":
    client = RoutingClient()

    client_common.main("routing", client)
