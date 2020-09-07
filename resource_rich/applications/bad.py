import logging
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("periodic-bad")
logger.setLevel(logging.DEBUG)

class PeriodicBad:
    def __init__(self, duration, name):
        self.duration = duration
        self.name = name

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
        except asyncio.CancelledError:
            pass
