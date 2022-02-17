import time
import threading
import sys

import pynrfjprog.HighLevel
import pynrfjprog.APIError

DEFAULT_BLOCK_SIZE = 1024
SECONDS_PER_READ = 0.010
SECONDS_PER_WRITE = 0.010

class RTT:
    """
    RTT communication class
    Based off: https://github.com/thomasstenersen/pyrtt-viewer/blob/master/pyrtt-viewer
    """

    def __init__(self, probe, channel, block_size=DEFAULT_BLOCK_SIZE):
        self.probe = probe
        self.channel = channel
        self.close_event = None
        self.writer_thread = None
        self.reader_thread = None
        self.block_size = block_size

    def _writer(self):
        while not self.close_event.is_set():
            data = sys.stdin.readline()#.strip("\n")
            #print(f"WRITER:{data!r}")
            if data:
                written = self.probe.rtt_write(self.channel, data)
                assert written == len(data)

            time.sleep(SECONDS_PER_WRITE)

    def _reader(self):
        while not self.close_event.is_set():
            data = self.probe.rtt_read(self.channel, self.block_size)
            #print(f"READER:{data!r}")
            if not data:
                time.sleep(SECONDS_PER_READ)
                continue

            sys.stdout.write(data)#, flush=True)
            sys.stdout.flush()

    def run(self):
        self.close_event = threading.Event()
        self.close_event.clear()
        self.reader_thread = threading.Thread(target=self._reader)
        self.reader_thread.start()
        self.writer_thread = threading.Thread(target=self._writer)
        self.writer_thread.start()

        try:
            while self.reader_thread.is_alive() or \
                  self.writer_thread.is_alive():
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.close_event.set()
            self.reader_thread.join()
            self.writer_thread.join()

def term_nrf(mote: int, channel: int=0, block_size: int=DEFAULT_BLOCK_SIZE):
    with pynrfjprog.HighLevel.API() as api:
        with pynrfjprog.HighLevel.DebugProbe(api, mote) as probe:
            probe.rtt_start()

            # Wait for rtt to be properly setup
            while not probe.rtt_is_control_block_found():
                time.sleep(0.01)

            try:
                rtt = RTT(probe, 0)
                rtt.run()
                """while True:
                    start = time.monotonic()

                    data = probe.rtt_read(channel, block_size)
                    if data:
                        print(data, end="", flush=("\n" in data))

                    taken = time.monotonic() - start

                    if taken < SECONDS_PER_READ:
                        time.sleep(SECONDS_PER_READ - taken)"""
            finally:
                probe.rtt_stop()
