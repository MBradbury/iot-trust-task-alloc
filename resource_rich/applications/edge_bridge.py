#!/usr/bin/env python3

import logging
import asyncio
import signal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("edge-bridge")
logger.setLevel(logging.DEBUG)

edge_marker = "!"
edge_server_port = 10_000

class NodeSerialBridge:
    def __init__(self):
        self.proc = None
        self.server = None

        self.applications = {}

    async def start(self):
        # Start a server that applications can connect to
        self.server = await asyncio.start_server(
            self._handle_application_conn,
            'localhost',
            edge_server_port)

        addr = self.server.sockets[0].getsockname()
        logger.info(f'Serving on {addr}')

        # Start processing serial output from edge sensor node
        self.proc = await asyncio.create_subprocess_shell(
            "~/pi-client/tools/pyterm -b 115200 -p /dev/ttyUSB0",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE)

    async def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            await self.proc.wait()
            self.proc = None

        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _process_serial_output(self, line: str):
        logger.debug(f"process_edge_output: {line}")
        application_name, length, payload = line.split(":", 2)

        try:
            # Find application to send to
            writer = self.applications[application_name]

            # Send the payload
            writer.write(f"{payload}\n".encode('utf-8'))
            await writer.drain()

        except KeyError:
            logger.warn(f"Unable to find local application {application_name} to forward message to")

    async def _run_serial(self):
        async for output in self.proc.stdout:
            line = output.decode('utf-8').rstrip()

            if line.startswith(edge_marker):
                await self._process_serial_output(line[len(edge_marker):])
            else:
                # A log message so print it out
                print(line)

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

def main(services):
    logger.info("Starting edge serial bridge")

    loop = asyncio.get_event_loop()

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, services)))

    try:
        for service in services:
            loop.create_task(do_run(service))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the edge serial bridge.")


if __name__ == "__main__":
    bridge = NodeSerialBridge()

    main([bridge])
