#!/usr/bin/env python3
# Initially inspired by: https://github.com/adafruit/Adafruit_Adalink/blob/master/adalink/cores/nrf52840.py

import sys

import pynrfjprog.HighLevel
import pynrfjprog.APIError
from pynrfjprog.Parameters import ReadbackProtection

class NRFCommon:
    BYTEORDER = 'little'

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

    def __init__(self, probe):
        self.probe = probe
        self.ficr_cache = None

    def _cached_read(self, address: int, length: int):
        if self.ficr_cache is None:
            self.ficr_cache = self.probe.read(self.FICR, self.FICR_LENGTH)
            assert len(self.ficr_cache) == self.FICR_LENGTH

        if address >= self.FICR and address + length <= self.FICR + self.FICR_LENGTH:
            offset = address - self.FICR 
            result = self.ficr_cache[offset:offset+length]

            # To match read, length of 4 needs to be converted into an int
            if length == 4:
                result = int.from_bytes(result, self.BYTEORDER)

            return result

        return None

    def _read(self, address: int, length: int):
        result = self._cached_read(address, length)
        if result is None:
            result = self.probe.read(address, length)
        return result

    def _readmem(self, offset: int, num: int, fn) -> str:
        try:
            mem = self._read(self.FICR + offset, num)
            return fn(mem)
        except pynrfjprog.APIError.APIError as ex:
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
            lambda mem: self.SRAM_LOOKUP.get(int.from_bytes(mem, self.BYTEORDER), mem.hex()))

    def flash(self):
        return self._readmem(self.FLASH_OFFSET, 2,
            lambda mem: self.FLASH_LOOKUP.get(int.from_bytes(mem, self.BYTEORDER), mem.hex()))

    def package(self):
        return self._readmem(self.PACKAGE_OFFSET, 2,
            lambda mem: self.PACKAGE_LOOKUP.get(int.from_bytes(mem, self.BYTEORDER), mem.hex()))

    def did(self):
        try:
            did = self._read(self.FICR + self.DEVICE_ID_OFFSET_LOW, 8)
            did.reverse()
            return did.hex()
        except pynrfjprog.APIError.APIError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def addr(self):
        try:
            addr = self._read(self.FICR + self.ADDR_OFFSET_LOW, 8)
            return addr.hex(":")
        except pynrfjprog.APIError.APIError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def contikieui64(self):
        # See: https://github.com/contiki-ng/contiki-ng/blob/develop/arch/cpu/nrf/sys/linkaddr-arch.c#L62
        NORDIC_SEMI_VENDOR_OUI = 0xF4CE36.to_bytes(3, 'big')

        try:
            addr = self._read(self.FICR + self.ADDR_OFFSET_LOW, 8)
            return (NORDIC_SEMI_VENDOR_OUI + addr[4:5] + addr[0:4]).hex(":")
        except pynrfjprog.APIError.APIError as ex:
            print(ex, file=sys.stderr)
            return "Err"

    def details(self):
        result = {
            #"Part ID": self.part(),
            "Device ID": self.did(),
            "Variant": self.variant(),
        }

        if hasattr(self, "PACKAGE_OFFSET"):
            result["Package"] = self.package()

        result.update({
            #"SRAM": self.sram(),
            #"Flash": self.flash(),
            "MAC": self.addr(),
            "CONTIKI EUI64": self.contikieui64(),
        })

        return result

class NRF52(NRFCommon):
    # https://infocenter.nordicsemi.com/topic/ps_nrf52833/ficr.html?cp=4_1_0_3_3
    FICR = 0x10000000
    FICR_LENGTH = 0x11D

    PART_OFFSET = 0x100
    VARIANT_OFFSET = 0x104
    PACKAGE_OFFSET = 0x108
    RAM_OFFSET = 0x10C
    FLASH_OFFSET = 0x110
    DEVICE_ID_OFFSET_LOW = 0x60
    ADDR_OFFSET_LOW = 0xa4

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
    FICR = 0x00FF0000
    FICR_LENGTH = 0x304 + 0x8

    PART_OFFSET = 0x20C
    VARIANT_OFFSET = 0x210
    PACKAGE_OFFSET = 0x214
    RAM_OFFSET = 0x218
    FLASH_OFFSET = 0x21C
    DEVICE_ID_OFFSET_LOW = 0x204
    ADDR_OFFSET_LOW = 0x2A4

    # Package ID value to name mapping.
    PACKAGE_LOOKUP = {
        0x2000: 'QKxx - 94-pin aQFN',
        0x2005: 'CLxx - WLCSP',
        0xFFFFFFFF: 'Unspecified'
    }

    # Note:
    # https://devzone.nordicsemi.com/f/nordic-q-a/66561/how-read-nrf_ficr-in-non-secure-core-nrf5340
    # https://infocenter.nordicsemi.com/topic/errata_nRF5340_EngA/ERR/nRF5340/EngineeringA/latest/anomaly_340_51.html

class NRF9160(NRFCommon):
    # https://infocenter.nordicsemi.com/topic/ps_nrf9160/ficr.html
    FICR = 0x00FF0000
    FICR_LENGTH = 0x304 + 0x8

    PART_OFFSET = 0x140
    VARIANT_OFFSET = 0x148
    RAM_OFFSET = 0x218
    FLASH_OFFSET = 0x21C
    DEVICE_ID_OFFSET_LOW = 0x204
    ADDR_OFFSET_LOW = 0x300

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

def motelist_nrf() -> list:
    result = []

    with pynrfjprog.HighLevel.API() as api:
        for node_id in api.get_connected_probes():
            with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
                probe_info = probe.get_probe_info()
                device_info = probe.get_device_info()

                node_info = {
                    "Serial": probe_info.serial_number,
                    "Speed (kHz)": probe_info.clockspeed_khz,
                    "COM": ",".join([com_port.path for com_port in probe_info.com_ports]),
                    "Type": device_info.device_type.name,
                    "Family": device_info.device_family.name,
                    "RBP": probe.get_readback_protection().name,
                    #"1": device_info.code_address,
                    #"2": device_info.code_page_size,
                    "ROM (KiB)": device_info.code_size / 1024,
                    #"3": device_info.uicr_address,
                    #"4": device_info.info_page_size,
                    #"5": device_info.code_ram_present,
                    #"6": device_info.code_ram_address,
                    #"7": device_info.data_ram_address,
                    "RAM (KiB)": device_info.ram_size / 1024,
                    #"8": device_info.qspi_present,
                    #"9": device_info.xip_address,
                    #"0": device_info.xip_size,
                    #"-": device_info.pin_reset_pin,
                }

                # Won't be able to do this with readback protection
                if probe.get_readback_protection() == ReadbackProtection.NONE:
                    information_getter = get_information_getter(device_info.device_type.name)
                    if information_getter is not None:
                        info = information_getter(probe)
                        node_info.update(info.details())

                result.append(node_info)

    return result

def print_motelist_nrf(output: str="table"):
    details = motelist_nrf()

    if output == "table":
        from tabulate import tabulate

        headers = []
        for detail in details:
            for k in detail.keys():
                if k not in headers:
                    headers.append(k)

        table = [[detail.get(header, "N/A") for header in headers] for detail in details]

        print(tabulate(table, headers, tablefmt="github"))

    elif output == "json":
        import json
        print(json.dumps(details))

    else:
        raise RuntimeError(f"Unknown format type {output}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='NRF Motelist')
    parser.add_argument("--output",
                        choices=["table", "json"],
                        default="table",
                        help="The output style")
    args = parser.parse_args()

    print_motelist_nrf(args.output)
