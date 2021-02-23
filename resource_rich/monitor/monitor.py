#!/usr/bin/env python3

from monitor_impl import MonitorBase

import logging
import asyncio
import signal
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("monitor")
logger.setLevel(logging.DEBUG)

class Monitor(MonitorBase):
    def __init__(self, name, log_dir=".", mote="/dev/ttyUSB0", no_dbg_log=False):
        super().__init__(name, log_dir=log_dir)

        self.proc = None
        self.previous_out = None

        self.mote = mote

        self.debug_log_file = None if no_dbg_log else open(f"{log_dir}/{name}-debug.log", "w")

    async def start(self):
        # Start processing serial output from edge sensor node
        self.proc = await asyncio.create_subprocess_shell(
            os.path.expanduser("~/pi-client/tools/pyterm") + f" -b 115200 -p {self.mote}",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE)

    async def stop(self):
        if self.debug_log_file is not None:
            self.debug_log_file.close()

        super().close()

        # Stop the serial line
        if self.proc is not None:
            self.proc.terminate()
            await self.proc.wait()
            self.proc = None

    async def run(self):
        loop = asyncio.get_event_loop()

        async for output in self.proc.stdout:
            # Exit if the event loop has stopped
            if not loop.is_running():
                break

            line = output.decode('utf-8').rstrip()

            self.write(line)

            # Regular log
            if not self.stop_further_processing:
                print(line)

                if self.debug_log_file is not None:
                    print(line, file=self.debug_log_file, flush=True)

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
    logger.info("Starting sensor node monitor")

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
        logger.info("Successfully shutdown the monitor.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Monitor')
    parser.add_argument('name', type=str, help='The name of this monitor')
    parser.add_argument('--log-dir', type=str, default=".", help='The location the logs will be stored')
    parser.add_argument("--mote", default="/dev/ttyUSB0", help="The mote to log output from.")
    parser.add_argument("--no-dbg-log", action="store_true", default=False, help="Do not create a log file")

    args = parser.parse_args()

    monitor = Monitor(args.name, log_dir=args.log_dir, mote=args.mote, no_dbg_log=args.no_dbg_log)

    main(monitor)
