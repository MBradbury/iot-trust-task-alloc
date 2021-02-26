from __future__ import annotations

import logging
import asyncio
import signal
import ipaddress
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
import math
import base64

import cbor2
from runstats import Statistics

from config import application_edge_marker, serial_sep, edge_server_port

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-client")
logger.setLevel(logging.DEBUG)

class Client:

    # This comes from Contiki-NG's circular buffer
    # Currently there is no way to increase this value
    max_serial_len = 127

    task_stats_prefix = f"app{serial_sep}stats{serial_sep}"

    def __init__(self, name, task_runner, max_workers=2):
        self.name = name
        self.reader = None
        self.writer = None

        self.message_prefix = f"{application_edge_marker}{self.name}{serial_sep}"

        self.stats = Statistics()
        self.executor = ProcessPoolExecutor(max_workers=max_workers)
        self._task_runner = task_runner

        self.ack_cond = asyncio.Condition()
        self.response_lock = asyncio.Lock()

        self.was_cancelled = False

    async def start(self):
        self.reader, self.writer = await asyncio.open_connection('localhost', edge_server_port)

        # Need to inform bridge of what application we represent
        await self.write(f"{self.name}\n")

        # Once started, we need to inform the edge of this application's availability
        await self._inform_application_started()

    async def run(self):
        while not self.reader.at_eof():
            line = await self.reader.readline()

            # Check if the endpoint closed on us
            if not line:
                logger.info("Connection closed")
                break

            line = line.decode("utf-8").rstrip()

            # Process ack
            if line.endswith(f"{serial_sep}ack"):
                async with self.ack_cond:
                    self.ack_cond.notify()
                continue

            # Process cancel
            if line.endswith(f"{serial_sep}cancel"):
                self.was_cancelled = True
                continue

            # Create task here to allow multiple jobs from clients to be
            # processed simultaneously (if they wish)
            asyncio.create_task(self.receive(line))

    async def stop(self):
        self.executor.shutdown()

        # When stopping, we need to inform the edge that this application is no longer available
        await self._inform_application_stopped()

        self.writer.close()
        await self.writer.wait_closed()

        self.reader = None
        self.writer = None

    async def receive(self, message: str):
        try:
            dt, src, payload_len, payload = message.split(serial_sep, 3)

            dt = datetime.fromisoformat(dt)
            src = ipaddress.IPv6Address(src)
            payload_len = int(payload_len)
            payload = bytes.fromhex(payload)

            if len(payload) != payload_len:
                logger.error(f"Incorrect payload length, expected {payload_len}, actual {len(payload)}")
                return

            payload = cbor2.loads(payload)

            logger.debug(f"Received task at {dt} from {src} <payload={payload}>")

        except Exception as ex:
            logger.error(f"Failed to parse message '{message}' with {ex}")
            return

        loop = asyncio.get_running_loop()
        task_result = await loop.run_in_executor(self.executor, self._task_runner, (src, dt, payload))

        (dest, message_response, duration) = task_result

        # Update the average time taken to perform jobs
        # TODO: should this be EWMA?
        self.stats.push(duration)

        # Only 1 response can be sent at a given time
        async with self.response_lock:
            await self._send_result(dest, message_response)

    async def _send_result(self, dest, message_response):
        raise NotImplementedError()

    async def _receive_ack(self):
        async with self.ack_cond:
            await self.ack_cond.wait()

    def _check_and_reset_cancelled(self) -> bool:
        result = self.was_cancelled
        self.was_cancelled = False
        return result

    async def write(self, message: str):
        logger.debug(f"Writing {message!r} of length {len(message)}")
        encoded_message = message.encode("utf-8")

        if len(encoded_message) > self.max_serial_len:
            logger.warn(f"Encoded message is longer ({len(encoded_message)}) than the maximum allowed length ({self.max_serial_len}) it will be truncated")

        self.writer.write(encoded_message)
        await self.writer.drain()

    async def _write_to_application(self, message: str, application_name: Optional[str]=None):
        # By default send this message to the application this process represents
        if not application_name:
            application_name = self.name

        await self.write(f"{application_edge_marker}{application_name}{serial_sep}{message}\n")

    async def _inform_application_started(self, application_name: Optional[str]=None):
        await self._write_to_application("start", application_name=application_name)

    async def _inform_application_stopped(self, application_name: Optional[str]=None):
        await self._write_to_application("stop", application_name=application_name)

    async def _write_task_stats(self):
        await self._write_to_application(f"{self.task_stats_prefix}{self._stats_string()}")
        await self._receive_ack()

    def _stats_string(self) -> str:
        try:
            variance = int(math.ceil(self.stats.variance()))
        except ZeroDivisionError:
            variance = 0

        mean = int(math.ceil(self.stats.mean()))
        maximum = int(math.ceil(self.stats.maximum()))
        minimum = int(math.ceil(self.stats.minimum()))

        data = (mean, maximum, minimum, variance)

        return base64.b64encode(cbor2.dumps(data)).decode("utf-8")


async def do_run(service):
    await service.start()
    await service.run()

async def shutdown(signal, loop, services):
    """Cleanup tasks tied to the service's shutdown."""
    logger.info(f"Received exit signal {signal.name}...")

    logger.info(f"Stopping services tasks...")
    await asyncio.gather(*[service.stop() for service in services], return_exceptions=True)

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    logger.info(f"Cancelling {len(tasks)} outstanding tasks...")
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info(f"Finished cancelling tasks!")

    loop.stop()

def exception_handler(loop, context, services):
    logger.info(f"Exception raised: {context}")

    # TODO: Gracefully stop services and notify sensor node we have shutdown
    #loop.create_task(asyncio.gather(*[service.stop() for service in services], return_exceptions=True))

def main(name, service):
    logger.info(f"Starting {name} application")

    loop = asyncio.get_event_loop()

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, [service])))

    loop.set_exception_handler(lambda l, c: exception_handler(l, c, [service]))

    try:
        loop.run_until_complete(do_run(service))
    finally:
        loop.close()
        logger.info(f"Successfully shutdown the {name} application.")
