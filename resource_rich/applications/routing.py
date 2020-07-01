#!/usr/bin/env python3

import cbor2
from pyroutelib3 import Router

import logging
from datetime import datetime
import ipaddress
from multiprocessing import Process, Queue, Event

import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-routing")
logger.setLevel(logging.DEBUG)

serial_sep = "|"

class RoutingClient(client_common.Client):
    def __init__(self):
        super().__init__("routing")

        self.queue = Queue()

        self.proc = Process(target=self._processor)
        self.proc.daemon = True

        self.shutdown_event = Event()

    async def start(self):
        await super().start()

        self.proc.start()

    async def stop(self):
        # Inform the process we are shutting down
        self.shutdown_event.set()

        # Stop the queue
        self.queue.close()
        self.queue.join_thread()

        # Try to stop the process cleanly, but if that fails kill it
        self.proc.join(timeout=0.5)
        if self.proc.exitcode is None:
            self.proc.kill()

        await super().stop()

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

        # Add message to queue to be processed
        self.queue.put(task)

    def _processor(self):
        while not self.shutdown_event.is_set():
            try:
                task = self.queue.get(block=True, timeout=0.05)
            except queue.Empty:
                continue

            # Do task
            (src, routing_source, routing_destination) = task

            router = Router("car")

            start = router.findNode(routing_source[0], routing_source[1])
            end = router.findNode(routing_destination[0], routing_destination[1])

            # TODO: Need to force cbor to encode floats using 32-bit at maximum

            status, route = router.doRoute(start, end)
            if status == "success":
                route = list(map(router.nodeLatLon, route))
                encoded_route = cbor2.encoder.dumps((1, route))
            elif status == "no_route":
                encoded_route = cbor2.encoder.dumps((2, []))
            elif status == "gave_up":
                encoded_route = cbor2.encoder.dumps((3, []))
            else:
                logger.error(f"Unknown result '{status}'")
                encoded_route = cbor2.encoder.dumps((4, []))

            # TODO: send encoded_route back to edge sensor node

if __name__ == "__main__":
    client = RoutingClient()

    client_common.main("routing", client)
