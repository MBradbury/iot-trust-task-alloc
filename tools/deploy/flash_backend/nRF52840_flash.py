#!/usr/bin/env python3

import subprocess
from pathlib import Path

import pynrfjprog.HighLevel
from pynrfjprog.Parameters import ProgramOptions, VerifyAction, EraseAction, ResetAction

def get_serial_number_for_mote(mote: str) -> int:
    with pynrfjprog.HighLevel.API() as api:
        for node_id in api.get_connected_probes():
            with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
                device_info = probe.get_device_info()

                # Make sure to only allow flashing to appropriate devices
                if not device_info.device_type.name.startswith("NRF52840"):
                    continue

                probe_info = probe.get_probe_info()

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

    serial_number = int(serial_number)

    program_options = ProgramOptions(
        verify=VerifyAction.VERIFY_READ,
        erase_action=EraseAction.ERASE_ALL,
        qspi_erase_action=EraseAction.ERASE_NONE,
        reset=ResetAction.RESET_SYSTEM
    )

    with pynrfjprog.HighLevel.API() as api:
        with pynrfjprog.HighLevel.DebugProbe(api, serial_number) as probe:
            probe.program(filename, program_options)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to nRF52840.')
    parser.add_argument("filename", help="The path to the binary to flash.")

    parser.add_argument("--serial-number", default=None, required=False, help="The serial number of the mote to flash")
    parser.add_argument("--mote", default=None, required=False, help="The mote to flash.")

    args = parser.parse_args()

    flash_nrf52840(filename, mote=mote, serial_number=args.serial_number)
