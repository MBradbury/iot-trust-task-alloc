#!/usr/bin/env python3

import pynrfjprog.HighLevel
from pynrfjprog.Parameters import ProgramOptions, VerifyAction, EraseAction, ResetAction

def flash_nrf(filename: str, serial_number: str):
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

            probe.reset()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to nrf.')
    parser.add_argument("filename", help="The path to the binary to flash.")
    parser.add_argument("serial-number", required=True, help="The serial number of the mote to flash")

    args = parser.parse_args()

    flash_nrf(args.filename, args.serial_number)
