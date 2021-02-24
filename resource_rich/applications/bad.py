import logging
import asyncio

from config import edge_marker
from client_common import Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bad-application")
logger.setLevel(logging.DEBUG)

class PeriodicBad:
    def __init__(self, duration, name, cb=None):
        self.duration = duration
        self.name = name
        self.cb = cb

        # Start off being good
        self.is_bad = False
        self.periodic_task = None

    async def start(self):
        if self.duration == float('inf'):
            # Always bad
            self.is_bad = True
        else:
            self.periodic_task = asyncio.create_task(self._periodic())

        logger.info(f"{self.name} becoming {'bad' if self.is_bad else 'good'}")

    async def shutdown(self):
        if self.periodic_task is not None:
            self.periodic_task.cancel()
            try:
                await self.periodic_task
            except asyncio.CancelledError:
                pass

    async def _periodic(self):
        loop = asyncio.get_running_loop()

        try:
            await asyncio.sleep(self.duration)

            while True:
                start = loop.time()

                self.is_bad = not self.is_bad

                logger.info(f"{self.name} becoming {'bad' if self.is_bad else 'good'}")

                if self.cb:
                    self.cb()

                end = loop.time()

                # Avoid drift by calculating the time it took to execute the task
                to_sleep_for = max(self.duration - (end - start), 0)
                await asyncio.sleep(to_sleep_for)

        except asyncio.CancelledError:
            logger.warning(f"Cancelling periodic task")
            raise

class FakeRestartClient(Client):
    async def _fake_restart_application(self, wait_duration: float):
        logger.info("Performing fake restart of the application...")

        try:
            await self._inform_application_stopped()

            await asyncio.sleep(wait_duration)

            await self._inform_application_started()
        except asyncio.CancelledError:
            logger.warning(f"Cancelling _fake_restart_application task")
            raise

        logger.info("Finished performing fake restart of the application!")

    async def _fake_restart_server(self, wait_duration: float):
        logger.info("Performing fake restart of the server...")

        try:
            await self._inform_edge_bridge_stopped()

            await asyncio.sleep(wait_duration)

            await self._inform_edge_bridge_started()
        except asyncio.CancelledError:
            logger.warning(f"Canelling _fake_restart_server task")
            raise

        logger.info("Finished performing fake restart of the server!")

    # Taken from edge_bridge.py
    async def _inform_edge_bridge_started(self):
        await self.write(f"{edge_marker}start\n")
        logger.debug("Sent fake start event")

    # Taken from edge_bridge.py
    async def _inform_edge_bridge_stopped(self):
        await self.write(f"{edge_marker}stop\n")
        logger.debug("Sent fake stop event")

class PeriodicFakeRestart:
    def __init__(self, kind: str, duration, period, client: FakeRestartClient):
        self.kind = kind
        self.duration = duration
        self.period = period
        self.client = client

        self.periodic_task = None

    async def start(self):
        self.periodic_task = asyncio.create_task(self._periodic())

    async def shutdown(self):
        if self.periodic_task is not None:
            self.periodic_task.cancel()
            try:
                await self.periodic_task
            except asyncio.CancelledError:
                pass

            self.periodic_task = None

    async def _periodic(self):
        loop = asyncio.get_running_loop()

        logger.info(f"Starting periodic {self.kind} fake restart every {self.period}s for {self.duration}s")

        try:
            await asyncio.sleep(self.period)

            while True:
                start = loop.time()

                if self.kind == "application":
                    await self.client._fake_restart_application(self.duration)
                elif self.kind == "server":
                    await self.client._fake_restart_server(self.duration)
                else:
                    raise RuntimeError(f"Unknown fake restart kind {self.kind}")

                end = loop.time()

                # Avoid drift by calculating the time it took to execute the task
                to_sleep_for = max(self.period - (end - start), 0)
                await asyncio.sleep(to_sleep_for)

        except asyncio.CancelledError:
            logger.warning(f"Cancelling periodic task")
            raise
