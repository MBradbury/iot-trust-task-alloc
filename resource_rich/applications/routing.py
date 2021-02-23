#!/usr/bin/env python3

import cbor2
from pyroutelib3 import Router

import logging
import struct
import time
import math
import base64
from more_itertools import chunked

from config import serial_sep
import client_common

NAME = "routing"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"app-{NAME}")
logger.setLevel(logging.DEBUG)

def truncate_float(x: float) -> float:
    return struct.unpack("f", struct.pack("f", x))[0]

def _format_route(route):
    # By default using canonical=True will try to format floats
    # in the smallest possible representation.
    # As we only plan on using 4 byte floats on the sensor nodes,
    # we can save space by forcing the coordinates to fit in a 4 byte float.
    return [
        (truncate_float(lat), truncate_float(lon))
        for (lat, lon)
        in route
    ]

def _task_runner(task):
    (src, dt, (node_time, routing_source, routing_destination)) = task

    logger.debug(f"Received message at {dt} from {src} <node_time={node_time}, "
            f"routing_source={routing_source}, "
            f"routing_destination={routing_destination}>")

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
    duration = end_timer - start_timer

    encoded_route_len = 0 if encoded_route[1] is None else len(encoded_route[1])
    logger.debug(f"Job {task} took {duration} seconds with status {status} route length = {encoded_route_len}")

    return (src, encoded_route, duration)

class RoutingClient(client_common.Client):

    task_resp1_prefix = f"app{serial_sep}resp1{serial_sep}"
    task_resp2_prefix = f"app{serial_sep}resp2{serial_sep}"

    coap_max_chunk_size = 256

    def __init__(self):
        super().__init__(NAME, task_runner=_task_runner, max_workers=2)

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
            route_encoded_length = len(cbor2.encoder.dumps(route, canonical=True))

            # We need to set this sufficiently high to prevent crashes in the client
            # I think this is because the code below leads to longer than expected packet lengths
            assumed_coap_chunk_overhead = 50

            num_coap_packets = route_encoded_length / (self.coap_max_chunk_size - assumed_coap_chunk_overhead)
            elements_per_coap_packet = math.floor(len(route) / num_coap_packets)

            route_chunks = list(chunked(route, elements_per_coap_packet))

            not_cancelled = await self._write_task_result_result(dest, status, len(route_chunks))

            # Keep going if not cancelled
            if not_cancelled:
                for i, route_chunk in enumerate(route_chunks):
                    not_cancelled = await self._write_task_result_chunk(i, len(route_chunks), route_chunk)

                    # Stop if cancelled
                    if not not_cancelled:
                        break
        else:
            not_cancelled = await self._write_task_result_result(dest, status, 0)

        if not not_cancelled:
            logger.warning("Result delivered too late, IoT device asked to cancel task")

    async def _write_task_result_result(self, dest, status, n) -> bool:
        await self._write_to_application(f"{self.task_resp1_prefix}{dest}{serial_sep}{n}{serial_sep}{status}")
        await self._receive_ack()

        # Only want to continue if we did not receive a cancel before the ack
        return not self._check_and_reset_cancelled()

    async def _write_task_result_chunk(self, i: int, n: int, route_chunk) -> bool:
        # Need canonical to fit floats into smallest space possible
        # Could considuer using https://github.com/allthingstalk/cbor/blob/master/CBOR-Tag103-Geographic-Coordinates.md
        # but is likely best to avoid the additional overhead
        cbor_encoded = cbor2.encoder.dumps(route_chunk, canonical=True)

        if len(cbor_encoded) > self.coap_max_chunk_size:
            logger.error(f"Encoded CBOR is too long ({cbor_encoded} > {self.coap_max_chunk_size}")

        b64_encoded = base64.b64encode(cbor_encoded).decode("utf-8")

        # Each coap packet route chunk now needs to be split up into multiple serial writes
        prefix_len = len(f"{self.message_prefix}{self.task_resp2_prefix}")
        # 1 character for suffix newline character
        # 2 characters for initial array marker
        # 6 characters for coap chunk counter (assume XX/XX|)
        # 4 characters for serial chunk counter (assume X/X|)
        # 1 character for base64 overhead
        assumed_serial_write_overhead = prefix_len + 1 + 2 + 6 + 4 + 1

        num_serial_writes = len(b64_encoded) / (self.max_serial_len - assumed_serial_write_overhead)
        elements_per_serial_write = math.floor(len(cbor_encoded) / num_serial_writes)

        chunks = list(chunked(cbor_encoded, elements_per_serial_write))

        for j, serial_chunk in enumerate(chunks):

            # chunked makes the bytes a list of ints, so we need to put it back together, encode and convert to a string
            serial_chunk = base64.b64encode(bytes(serial_chunk)).decode("utf-8")

            # Send task response back to edge sensor node
            await self._write_to_application(f"{self.task_resp2_prefix}{i}/{n}{serial_sep}{j}/{len(chunks)}{serial_sep}{serial_chunk}")
            await self._receive_ack()

            # If cancelled, then stop sending messages
            if self._check_and_reset_cancelled():
                return False

        return True


if __name__ == "__main__":
    client = RoutingClient()

    client_common.main(NAME, client)
