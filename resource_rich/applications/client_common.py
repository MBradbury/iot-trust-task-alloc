import logging
import asyncio
import signal

from config import application_edge_marker, serial_sep, edge_server_port

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-client")
logger.setLevel(logging.DEBUG)

class Client:
    def __init__(self, name):
        self.name = name
        self.reader = None
        self.writer = None

        self.max_serial_len = 128
        self.message_prefix = f"{application_edge_marker}{self.name}{serial_sep}"

    async def receive(self, message: str):
        raise NotImplementedError()

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

            # Create task here to allow multiple jobs from clients to be
            # processed simultaneously (fi they wish)
            asyncio.create_task(self.receive(line))

    async def stop(self):
        # When stopping, we need to inform the edge that this application is no longer available
        await self._inform_application_stopped()

        self.writer.close()
        await self.writer.wait_closed()

        self.reader = None
        self.writer = None

    async def write(self, message: str):
        logger.debug(f"Writing {message!r} of length {len(message)}")
        encoded_message = message.encode("utf-8")

        if len(encoded_message) > self.max_serial_len:
            logger.warn(f"Encoded message is longer ({len(encoded_message)}) than the maximum allowed length ({self.max_serial_len}) it will be truncated")

        self.writer.write(encoded_message)
        await self.writer.drain()

    async def _write_to_application(self, message: str):
        await self.write(f"{self.message_prefix}{message}\n")

    async def _inform_application_started(self):
        await self._write_to_application("start")

    async def _inform_application_stopped(self):
        await self._write_to_application("stop")


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

def main(name, main_service, services=None):
    if services is None:
        services = []

    logger.info(f"Starting {name} application")

    loop = asyncio.get_event_loop()

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, [main_service] + services)))

    loop.set_exception_handler(lambda l, c: exception_handler(l, c, [main_service] + services))

    try:
        for service in services:
            loop.create_task(do_run(service))
        loop.run_until_complete(do_run(main_service))
    finally:
        loop.close()
        logger.info(f"Successfully shutdown the {name} application.")
