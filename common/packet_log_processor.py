from datetime import datetime, timezone

class PacketLogProcessor:
    def __init__(self):
        self.previous_out = None

    def process_all(self, f):
        packets = []

        for line in f:
            result = self.process(line)
            if result is not None:
                packets.append(result)

        return zip(*packets)

    def process(self, line: str):
        line = line.rstrip()

        (time, kind, rest) = line.split(",", 2)

        if kind == "in":
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            length, message = rest.split(",")
            return self._process_in(int(length), bytes.fromhex(message), now=now)

        elif kind == "out":
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            length, message = rest.split(",")
            return self._process_out(int(length), bytes.fromhex(message), now=now)

        elif kind == "outres":
            now = datetime.now(timezone.utc) if time is None else datetime.fromisoformat(time)

            length, result = rest.split(",")
            return self._process_out_res(int(length), int(result), now=now)

        else:
            raise RuntimeError(f"Unknown line {line}")

    def _process_in(self, length: int, message: bytes, now: datetime):
        if length != len(message):
            logger.warning("Inconsistent length of received message")

        return (message, "rx", now)

    def _process_out(self, length: int, message: bytes, now: datetime):
        if length != len(message):
            logger.warning("Inconsistent length of sent message")

        self.previous_out = (now, length, message)

    def _process_out_res(self, length: int, result: int, now: datetime):
        if self.previous_out is None:
            logger.warning("Received out result, when no previous out message")
            return

        previous_now, previous_length, message = self.previous_out

        if previous_length != length:
            return

        self.previous_out = None

        # 0 is RADIO_TX_OK
        if result != 0:
            return

        return (message, "tx", previous_now)
