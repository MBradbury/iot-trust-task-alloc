#!/usr/bin/env python3
# Mostly implemented from: https://github.com/adafruit/Adafruit_Adalink/blob/master/adalink/cores/nrf52840.py

import subprocess
import sys

def readmem(node_id: str, mem: int, num_bytes: int) -> int:
    assert num_bytes <= 4

    command = f"nrfjprog --memrd {mem:#08x} --n 4 --snr {node_id}"
    memrd = subprocess.run(command,
                           shell=True,
                           capture_output=True,
                           text=True)

    # Expected output format
    # $ nrfjprog --memrd 0x100000A4 --n 4 --snr 683867147
    # 0x100000A4: 62319643                              |C.1b|

    if memrd.stderr:
        raise RuntimeError(memrd.stderr)

    word = memrd.stdout.split(" ")[1]

    return int(word, base=16)

class NRFCommon:
    SRAM_LOOKUP = {
        0x10: '16 KB',
        0x20: '32 KB',
        0x40: '64 KB',
        0x80: '128 KB',
        0x100: '256 KB',
        0x200: '512 KB',
        0xFFFFFFFF: 'Unspecified'
    }

    FLASH_LOOKUP = {
        0x80:  '128 KB',
        0x100: '256 KB',
        0x200: '512 KB',
        0x400: '1 MB',
        0x800: '2 MB',
        0xFFFFFFFF: 'Unspecified'
    }

    PART_LOOKUP = {
        0X52833: '52833',
        0X52840: '52840',
        0X5340: '5340',
        0X9160: '9160',
        0xFFFFFFFF: 'Unspecified'
    }

    def __init__(self, node_id: str):
        self.node_id = node_id

    def _readmem(self, offset, num, fn):
        try:
            mem = readmem(self.node_id, self.FCIR + offset, 4)
            return fn(mem)
        except RuntimeError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def part(self):
        return self._readmem(self.PART_OFFSET, 4,
            lambda mem: self.PART_LOOKUP.get(mem, f'{mem:#05X}'))

    def variant(self):
        # Variant encoded as 4 ASCII bytes
        def process(mem):
            if mem == 0xFFFFFFFF:
                return 'Unspecified'
            return mem.to_bytes(4, byteorder='big').decode("ascii")
        return self._readmem(self.VARIANT_OFFSET, 4, process)

    def sram(self):
        return self._readmem(self.RAM_OFFSET, 2,
            lambda mem: self.SRAM_LOOKUP.get(mem, f'{mem:#02X}'))

    def flash(self):
        return self._readmem(self.FLASH_OFFSET, 2,
            lambda mem: self.FLASH_LOOKUP.get(mem, f'{mem:#04X}'))

    def package(self):
        return self._readmem(self.PACKAGE_OFFSET, 2,
            lambda mem: self.PACKAGE_LOOKUP.get(mem, f'{mem:#04X}'))

    def did(self):
        try:
            did_high = readmem(self.node_id, self.FCIR + self.DEVICE_ID_OFFSET_LOW, 4)
            did_low  = readmem(self.node_id, self.FCIR + self.DEVICE_ID_OFFSET_HIGH, 4)
            return f'{did_high:08X}{did_low:08X}'
        except RuntimeError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def addr(self):
        try:
            addr_high = (readmem(self.node_id, self.FCIR + self.ADDR_OFFSET_HIGH, 4) & 0x0000ffff) | 0x0000c000
            addr_low  = readmem(self.node_id, self.FCIR + self.ADDR_OFFSET_LOW, 4)
            return '{0:02X}:{1:02X}:{2:02X}:{3:02X}:{4:02X}:{5:02X}'.format(
                (addr_high >>  8) & 0xFF,
                (addr_high >>  0) & 0xFF,
                (addr_low  >> 24) & 0xFF,
                (addr_low  >> 16) & 0xFF,
                (addr_low  >>  8) & 0xFF,
                (addr_low  >>  0) & 0xFF)
        except RuntimeError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def details(self):
        result = {
            "Part ID": self.part(),
            "Device ID": self.did(),
            "Variant": self.variant(),
        }

        if hasattr(self, "PACKAGE_OFFSET"):
            result["Package"] = self.package()

        result.update({
            "SRAM": self.sram(),
            "Flash": self.flash(),
            "MAC": self.addr(),
        })

        return result

class NRF52(NRFCommon):
    # https://infocenter.nordicsemi.com/topic/ps_nrf52833/ficr.html?cp=4_1_0_3_3
    FCIR = 0x10000000
    PART_OFFSET = 0x100
    VARIANT_OFFSET = 0x104
    PACKAGE_OFFSET = 0x108
    RAM_OFFSET = 0x10C
    FLASH_OFFSET = 0x110
    DEVICE_ID_OFFSET_LOW = 0x60
    DEVICE_ID_OFFSET_HIGH = 0x64
    ADDR_OFFSET_LOW = 0xa4
    ADDR_OFFSET_HIGH = 0xa8

class NRF52833(NRF52):
    # Package ID value to name mapping.
    PACKAGE_LOOKUP = {
        0x2004: 'QIxx - 7x7 73-pin aQFN',
        0x2007: 'QDxx - 5x5 40-pin QFN',
        0x2008: 'CJxx - 3.175 x 3.175 WLCSP',
        0xFFFFFFFF: 'Unspecified'
    }

class NRF52840(NRF52):
    # Package ID value to name mapping.
    PACKAGE_LOOKUP = {
        0x2004: 'QIxx - 73-pin aQFN',
        0xFFFFFFFF: 'Unspecified'
    }

    def nfc(self):
        return self._readmem(0x120C, 2,
            lambda mem: "NFC" if mem == 0xFFFFFFFF else "GPIO")

    def details(self):
        result = super().details()
        result.update({
            "NFC": self.nfc(),
        })

        return result
            
class NRF5340(NRFCommon):
    # https://infocenter.nordicsemi.com/topic/ps_nrf5340/chapters/ficr.network/doc/ficr.network.html?cp=3_0_0_5_3_0
    FCIR = 0x01FF0000
    PART_OFFSET = 0x20C
    VARIANT_OFFSET = 0x210
    PACKAGE_OFFSET = 0x214
    RAM_OFFSET = 0x218
    FLASH_OFFSET = 0x21C
    DEVICE_ID_OFFSET_LOW = 0x204
    DEVICE_ID_OFFSET_HIGH = 0x208
    ADDR_OFFSET_LOW = 0x2A4
    ADDR_OFFSET_HIGH = 0x2A8

    # Package ID value to name mapping.
    PACKAGE_LOOKUP = {
        0x2000: 'QKxx - 94-pin aQFN',
        0x2005: 'CLxx - WLCSP',
        0xFFFFFFFF: 'Unspecified'
    }

class NRF9160(NRFCommon):
    # https://infocenter.nordicsemi.com/topic/ps_nrf9160/ficr.html
    FCIR = 0x00FF0000
    PART_OFFSET = 0x140
    VARIANT_OFFSET = 0x148
    RAM_OFFSET = 0x218
    FLASH_OFFSET = 0x21C
    DEVICE_ID_OFFSET_LOW = 0x204
    DEVICE_ID_OFFSET_HIGH = 0x208
    ADDR_OFFSET_LOW = 0x300
    ADDR_OFFSET_HIGH = 0x304

    # No package


information_getters = {
    "NRF52833": NRF52833,
    "NRF52840": NRF52840,
    "NRF5340": NRF5340,
    "NRF9160": NRF9160,
}

def get_information_getter(device_version):
    for (node_type, information_getter) in information_getters.items():
        if device_version.startswith(node_type):
            return information_getter
    return None

def motelist():
    result = []

    node_ids = subprocess.run("nrfjprog --ids",
                              check=True,
                              shell=True,
                              capture_output=True,
                              text=True)
    node_ids = node_ids.stdout.strip().split("\n")

    for node_id in node_ids:
        deviceversion = subprocess.run(f"nrfjprog --deviceversion --snr {node_id}",
                                       check=True,
                                       shell=True,
                                       capture_output=True,
                                       text=True)

        device_version = deviceversion.stdout.strip()

        node_info = {
            "Node ID": node_id,
            "Device Version": device_version,
        }

        information_getter = get_information_getter(device_version)
        if information_getter is not None:
            info = information_getter(node_id)

            node_info.update(info.details())

        result.append(node_info)

    return result

def main():
    from tabulate import tabulate

    details = motelist()

    headers = []
    for detail in details:
        for k in detail.keys():
            if k not in headers:
                headers.append(k)

    table = [[detail.get(header, "N/A") for header in headers] for detail in details]

    print(tabulate(table, headers, tablefmt="github"))

if __name__ == "__main__":
    main()
