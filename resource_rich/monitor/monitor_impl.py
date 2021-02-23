import logging
from datetime import datetime, timezone
from enum import IntEnum

#from scapy.all import UDP, IPv6, ICMP
#from scapy.layers.inet6 import *
#from scapy.layers.dot15d4 import Dot15d4
#from scapy.layers.sixlowpan import *
#from scapy.contrib.coap import CoAP
#from scapy.contrib.rpl import *
#from scapy.contrib.rpl_metrics import *
#from scapy.utils import PcapWriter
#from scapy.config import conf
#
#conf.dot15d4_protocol = 'sixlowpan'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("monitor")
logger.setLevel(logging.DEBUG)

PCAP_LOG_MARKER = "#"

class RadioStatus(IntEnum):
    """
    Contiki-NG Radio Status
    See os/dev/radio.h
    """
    RADIO_TX_OK = 0
    RADIO_TX_ERR = 1
    RADIO_TX_COLLISION = 2
    RADIO_TX_NOACK = 3

class MonitorBase:
    def __init__(self, name, log_dir="."):
        self.previous_out = None
        self._stop = False

        self.packet_log_file = open(f"{log_dir}/{name}.packet.log", "w")

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def close(self):
        self.packet_log_file.close()

    def _process_in(self, length: int, message: bytes, now: datetime):
        if length != len(message):
            logger.warning("Inconsistent length of received message")

        print(f"{now},in,{length},{message.hex()}", file=self.packet_log_file, flush=True)

        self._output_packet(message, "rx", now)

    def _process_out(self, length: int, message: bytes, now: datetime):
        if length != len(message):
            logger.warning("Inconsistent length of sent message")

        print(f"{now},out,{length},{message.hex()}", file=self.packet_log_file, flush=True)

        self.previous_out = (now, length, message)

    def _process_out_res(self, length: int, result: int, now: datetime):
        print(f"{now},outres,{length},{result}", file=self.packet_log_file, flush=True)

        if self.previous_out is None:
            logger.warning("Received out result, when no previous out message")
            return

        previous_now, previous_length, message = self.previous_out

        if previous_length != length:
            return

        self.previous_out = None

        if result != RadioStatus.RADIO_TX_OK:
            return

        self._output_packet(message, "tx", previous_now)

    def _output_packet(self, message: bytes, kind: str, now: datetime):
        pass

    def write(self, line: str):
        line = line.rstrip()

        time = None

        # Line might start with a timestamp that we need to remove
        if " # " in line:
            (time, line) = line.split(" # ", 1)

        if line.startswith(PCAP_LOG_MARKER + "In|"):
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            _, length, message = line.split("|")
            self._process_in(int(length), bytes.fromhex(message), now=now)
            self.stop_further_processing = True

        elif line.startswith(PCAP_LOG_MARKER + "Out|"):
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            _, length, message = line.split("|")
            self._process_out(int(length), bytes.fromhex(message), now=now)
            self.stop_further_processing = True

        elif line.startswith(PCAP_LOG_MARKER + "OutRes|"):
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            _, length, result = line.split("|")
            self._process_out_res(int(length), int(result), now=now)
            self.stop_further_processing = True

        else:
            self.stop_further_processing = False

    def flush(self):
        self.packet_log_file.flush()
