#!/usr/bin/env python3

import logging
import asyncio
import signal
from datetime import datetime, timezone
import os

from config import edge_marker, application_edge_marker, serial_sep, edge_server_port

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("edge-bridge")
logger.setLevel(logging.DEBUG)

class NodeSerialBridge:
    def __init__(self):
        self.proc = None
        self.server = None

        self.applications = {}

    async def start(self):
        # Start processing serial output from edge sensor node
        self.proc = await asyncio.create_subprocess_shell(
            os.path.expanduser("~/pi-client/tools/pyterm") + " -b 115200 -p /dev/ttyUSB0",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE)

        await self._inform_edge_bridge_started()

        # Start a server that applications can connect to
        self.server = await asyncio.start_server(
            self._handle_application_conn,
            'localhost',
            edge_server_port)

        addr = self.server.sockets[0].getsockname()
        logger.info(f'Serving on {addr}')

    async def stop(self):
        # Stop the server, so applications cannot communicate with us
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

        # If we are being stopped, then inform the sensor node application
        await self._inform_edge_bridge_stopped()

        # Stop the serial line
        if self.proc is not None:
            self.proc.terminate()
            await self.proc.wait()
            self.proc = None

    async def _process_serial_output(self, now: datetime, line: str):
        logger.debug(f"process_edge_output: {line}")
        application_name, payload = line.split(serial_sep, 1)

        try:
            # Find application to send to
            writer = self.applications[application_name]

            # Send the payload and the created timestamp
            writer.write(f"{now.isoformat()}{serial_sep}{payload}\n".encode('utf-8'))
            await writer.drain()

        except KeyError:
            logger.warning(f"Unable to find local application {application_name} to forward message to")

    async def _run_serial(self):
        loop = asyncio.get_event_loop()

        async for output in self.proc.stdout:
            # Exit if the event loop has stopped
            if not loop.is_running():
                break

            line = output.decode('utf-8').rstrip()

            # Application message
            if line.startswith(application_edge_marker):
                now = datetime.now(timezone.utc)
                await self._process_serial_output(now, line[len(application_edge_marker):])

            # Edge message
            elif line.startswith(edge_marker):
                logger.warning(f"Don't know what to do with {line}")

            # Regular log
            else:
                print(line, flush=True)

    async def _run_applications(self):
        async with self.server:
            await self.server.serve_forever()

    async def run(self):
        t1 = asyncio.create_task(self._run_serial())
        t2 = asyncio.create_task(self._run_applications())

        await asyncio.gather(t1, t2)

    async def _handle_application_conn(self, reader, writer):
        try:
            addr = writer.get_extra_info('peername')
            logger.info(f"Connected to {addr}")

            application_name = (await reader.readline()).decode("utf-8").rstrip()
            logger.info(f"Application {application_name} is running on {addr}")
            self.applications[application_name] = writer

            # Read lines from the application and forward onto the serial line
            while not reader.at_eof():
                line = await reader.readline()
                self.proc.stdin.write(line)
                await self.proc.stdin.drain()

        finally:
            del self.applications[application_name]

    async def _inform_edge_bridge_started(self):
        line = f"{edge_marker}start\n".encode("utf-8")
        self.proc.stdin.write(line)
        await self.proc.stdin.drain()
        logger.debug("Sent start event")

    async def _inform_edge_bridge_stopped(self):
        line = f"{edge_marker}stop\n".encode("utf-8")
        self.proc.stdin.write(line)
        await self.proc.stdin.drain()
        logger.debug("Sent stop event")


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

def main(service):
    logger.info("Starting edge serial bridge")

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
        logger.info("Successfully shutdown the edge serial bridge.")


if __name__ == "__main__":
    bridge = NodeSerialBridge()

    main(bridge)
