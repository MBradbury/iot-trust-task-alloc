#!/usr/bin/env python3

import subprocess
from pathlib import Path
import csv
import io
import os

JLINK_DIR = Path("/opt/SEGGER/JLink")
JLINK_EXE = JLINK_DIR / "JLinkExe"

def write_flash_jlink(target):
    with open("flash.jlink", "w") as f:
        print(f"""loadfile {target}
r
g
q""", file=f)

def flash_nrf52840(filename, mote=None, serial_number=None):
    if (mote is None) == (serial_number is None):
        raise ArgumentError("Need to specify at most one of mote and serial number")

    # Need to find serial number for mote
    if mote is not None:
        assert serial_number is None

        motelist = subprocess.run(os.path.expanduser("~/bin/motelist/motelist.py --csv"),
                                  shell=True, check=True, capture_output=True)
        motelistreader = csv.DictReader(io.StringIO(motelist.stdout.decode("utf-8")), delimiter=";")

        for row in motelistreader:
            if row["Port"] == mote:
                serial_number = row["Serial"]
                break
        else:
            raise RuntimeError(f"Unable to find serial number for mote {mote}")

    opts = {
        "-Device": "NRF52",
        "-if": "swd",
        "-speed": "1000",
        "-SelectEmuBySN": serial_number,
    }

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    write_flash_jlink(filename)

    subprocess.check_call(f"{JLINK_EXE} {opts_str} -CommanderScript flash.jlink", shell=True)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to nRF52840.')
    parser.add_argument("filename", help="The path to the binary to flash.")

    parser.add_argument("--serial-number", default=None, required=False, help="The serial number of the mote to flash")
    parser.add_argument("--mote", default=None, required=False, help="The mote to flash.")

    #parser.add_argument("firmware_type", choices=["contiki", "riot"], help="The OS that was used to create the firmware.")

    args = parser.parse_args()

    flash_nrf52840(filename, mote=mote, serial_number=args.serial_number)
