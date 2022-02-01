#!/usr/bin/env python3

import subprocess
from pathlib import Path

import pynrfjprog.HighLevel
import pynrfjprog.APIError

JLINK_DIR = Path("/opt/SEGGER/JLink")
JLINK_EXE = JLINK_DIR / "JLinkExe"

def write_flash_jlink(target):

    # 1. Load binary
    #    https://wiki.segger.com/J-Link_Commander#LoadFile
    # 2. Issue reset via "ResetX" with a delay of 1000ms after reset
    #    https://wiki.segger.com/J-Link_Commander#Reset
    # 3. Start CPU via "Go"
    #    https://wiki.segger.com/J-Link_Commander#Go
    # 4-5 Show information
    # 6. Exit

    """
    Syntax: RSetType <type>

        Types:
        0 = NORMAL (Resets core & peripherals via SYSRESETREQ & VECTRESET bit.)
        1 = CORE (Resets the core only, not peripherals.)
        2 = RESETPIN (Resets core & peripherals using RESET pin.)
        3 = CONNECT UNDER RESET (Halts RESET Pin low when connecting to core)
        4 = HALT AFTER BTL (Resets core & peripherals, halts CPU after the bootloader.)
        5 = HALT BEFORE BTL (Resets core & peripherals, halts CPU before the bootloader.)
        6 = KINETIS (Reset via strategy NORMAL. Watchdog will be disabled after reset)
        7 = ADI HALT AFTER KERNEL (Resets core & peripherals, halts CPU after the ADI kernel.)
        8 = CORE AND PERIPHERALS (Resets core & peripherals via SYSRESETREQ bit only.)
        9 = LPC1200 (Reset via strategy normal. Watchdog will be disabled after reset)
        10 = S3FN60D (Reset via strategy normal. Watchdog will be disabled after reset)
        11 = LPC11A (Resets core & peripherals. Performs some special handling which is needed by some LPC11A bootloaders.)
        12 = Halter after BTL using WP (Resets core & peripherals via SYSRESETREQ. Halts CPU after BTL using WP.)
    """

    with open("flash.jlink", "w") as f:
        print(f"""LoadFile {target} 0x0
RSetType 0
ResetX 1000
Go
ShowFWInfo
ShowHWStatus
Exit""", file=f)

def get_serial_number_for_mote(mote: str) -> int:
    with pynrfjprog.HighLevel.API() as api:
        for node_id in api.get_connected_probes():
            with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
                probe_info = probe.get_probe_info()
                device_info = probe.get_device_info()

                # Make sure to only allow flashing to appropriate devices
                if not device_info.device_type.name.startswith("NRF52840"):
                    continue

                if mote in [com_port.path for com_port in probe_info.com_ports]:
                    return node_id

    raise RuntimeError(f"Unable to find serial number for mote {mote}")

def flash_nrf52840(filename, mote=None, serial_number=None):
    if (mote is None) == (serial_number is None):
        raise ArgumentError("Need to specify at most one of mote and serial number")

    # Need to find serial number for mote
    if mote is not None:
        assert serial_number is None
        serial_number = get_serial_number_for_mote(mote)

    opts = {
        "-Device": "nRF52840_xxAA",
        "-if": "swd",
        "-speed": 2000,
        "-SelectEmuBySN": serial_number,
    }

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    write_flash_jlink(filename)

    subprocess.run(f"{JLINK_EXE} {opts_str} -CommanderScript flash.jlink", shell=True, check=True)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to nRF52840.')
    parser.add_argument("filename", help="The path to the binary to flash.")

    parser.add_argument("--serial-number", default=None, required=False, help="The serial number of the mote to flash")
    parser.add_argument("--mote", default=None, required=False, help="The mote to flash.")

    args = parser.parse_args()

    flash_nrf52840(filename, mote=mote, serial_number=args.serial_number)
