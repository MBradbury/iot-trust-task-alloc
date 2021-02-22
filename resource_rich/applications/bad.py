import logging
import asyncio

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

    def start(self):
        if self.duration == float('inf'):
            # Always bad
            self.is_bad = True
        else:
            self.periodic_task = asyncio.create_task(self._periodic())

        logger.info(f"{self.name} becoming {'bad' if self.is_bad else 'good'}")

    def shutdown(self):
        if self.periodic_task is not None:
            self.periodic_task.cancel()

    async def _periodic(self):
        try:
            while True:
                await asyncio.sleep(self.duration)

                self.is_bad = not self.is_bad

                logger.info(f"{self.name} becoming {'bad' if self.is_bad else 'good'}")

                if self.cb:
                    self.cb()

        except asyncio.CancelledError:
            pass

class FakeRestartClient(Client):
    async def _fake_restart(self, wait_duration: float):
        try:
            await self._inform_application_stopped()

            await asyncio.sleep(wait_duration)

            await self._inform_application_started()
        except asyncio.CancelledError:
            pass

    def _do_fake_restart(self, wait_duration: float) -> asyncio.Task:
        return asyncio.create_task(self._fake_restart(wait_duration))
