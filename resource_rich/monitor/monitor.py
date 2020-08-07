#!/usr/bin/env python3

import logging
import asyncio
import signal
import datetime
import os

from scapy.all import UDP, IPv6, ICMP
from scapy.layers.inet6 import *
from scapy.layers.dot15d4 import Dot15d4
from scapy.layers.sixlowpan import *
from scapy.contrib.coap import CoAP
from scapy.contrib.rpl import *
from scapy.contrib.rpl_metrics import *
from scapy.utils import PcapWriter
from scapy.config import conf

conf.dot15d4_protocol = 'sixlowpan'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("monitor")
logger.setLevel(logging.DEBUG)

PCAP_LOG_MARKER = "#"

class Monitor:
    def __init__(self, name, log_dir="."):
        self.proc = None
        self.previous_out = None

        now = datetime.datetime.now(datetime.timezone.utc)
        now_str = now.strftime("%Y-%m-%d-%H-%M")

        self.debug_log_file = open(f"{log_dir}/{name}-{now_str}-debug.log", "w")
        self.packet_log_file = open(f"{log_dir}/{name}-{now_str}-packet.log", "w")
        self.pcap_log_file = PcapWriter(f"{log_dir}/{name}-{now_str}-data.pcap", sync=True)

    async def start(self):
        # Start processing serial output from edge sensor node
        self.proc = await asyncio.create_subprocess_shell(
            os.path.expanduser("~/pi-client/tools/pyterm") + " -b 115200 -p /dev/ttyUSB0",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE)

    async def stop(self):
        self.debug_log_file.close()
        self.packet_log_file.close()
        self.pcap_log_file.close()

        # Stop the serial line
        if self.proc is not None:
            self.proc.terminate()
            await self.proc.wait()
            self.proc = None

    def _process_in(self, length: int, message: bytes):
        if length != len(message):
            logger.warning("Inconsistent length of received message")

        now = datetime.datetime.now(datetime.timezone.utc)

        print(f"{now},in,{length},{message.hex()}", file=self.packet_log_file, flush=True)

        packet = Dot15d4(message)
        packet.time = now.timestamp()

        self.pcap_log_file.write(packet)

    def _process_out(self, length: int, message: bytes):
        if length != len(message):
            logger.warning("Inconsistent length of sent message")

        now = datetime.datetime.now(datetime.timezone.utc)

        print(f"{now},out,{length},{message.hex()}", file=self.packet_log_file, flush=True)

        self.previous_out = (now, length, message)

    def _process_out_res(self, length: int, result: int):
        now = datetime.datetime.now(datetime.timezone.utc)

        print(f"{now},outres,{length},{result}", file=self.packet_log_file, flush=True)

        if self.previous_out is None:
            logger.warning("Received out result, when no previous out message")
            return

        previous_now, previous_length, message = self.previous_out

        if previous_length != length:
            return

        self.previous_out = None

        if result == 0:
            return

        packet = Dot15d4(message)
        packet.time = previous_now.timestamp()

        self.pcap_log_file.write(packet)


    async def run(self):
        loop = asyncio.get_event_loop()

        async for output in self.proc.stdout:
            # Exit if the event loop has stopped
            if not loop.is_running():
                break

            line = output.decode('utf-8').rstrip()

            if line.startswith(PCAP_LOG_MARKER + "In|"):
                _, length, message = line.split("|")
                self._process_in(int(length), bytes.fromhex(message))

            elif line.startswith(PCAP_LOG_MARKER + "Out|"):
                _, length, message = line.split("|")
                self._process_out(int(length), bytes.fromhex(message))

            elif line.startswith(PCAP_LOG_MARKER + "OutRes|"):
                _, length, result = line.split("|")
                self._process_out_res(int(length), int(result))

            # Regular log
            else:
                print(line)
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

def main(services):
    logger.info("Starting sensor node monitor")

    loop = asyncio.get_event_loop()

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, services)))

    loop.set_exception_handler(lambda l, c: exception_handler(l, c, services))

    try:
        for service in services:
            loop.create_task(do_run(service))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the edge serial bridge.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Monitor')
    parser.add_argument('name', type=str, help='The name of this monitor')
    parser.add_argument('--log-dir', type=str, default=".", help='The location the logs will be stored')

    args = parser.parse_args()

    monitor = Monitor(args.name, log_dir=args.log_dir)

    main([monitor])
