#!/usr/bin/env python3
import subprocess
import os
import pathlib
import csv
import io
import os
import time

def get_serial_number_for_mote(mote: str) -> str:
    motelist = subprocess.run(os.path.expanduser("~/bin/motelist/motelist.py --csv"),
                              shell=True,
                              check=True,
                              capture_output=True)

    motelistreader = csv.DictReader(io.StringIO(motelist.stdout.decode("utf-8")),
                                    delimiter=";")

    for row in motelistreader:
        if row["Port"] == mote:
            return row["Serial"]

    raise RuntimeError(f"Unable to find serial number for mote {mote}")

def main_nrf52840(mote: str):
    # See: https://github.com/RIOT-OS/RIOT/blob/73ccd1e2e721bee38f958f8906ac32e5e1fceb0c/dist/tools/jlink/jlink.sh#L268

    JLINK_DIR = pathlib.Path("/opt/SEGGER/JLink")
    JLINK_EXE = JLINK_DIR / "JLinkExe"

    opts = {
        "-nogui": "1",
        "-exitonerror": "1",
        "-device": "NRF52",
        "-speed": "1000",
        "-if": "swd",
        "-jtagconf": "-1,-1",
        "-SelectEmuBySN": get_serial_number_for_mote(mote),
    }

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    jlink = subprocess.Popen(f"{JLINK_EXE} {opts_str} -CommanderScript jlink_term.seg",
                             cwd="tools/deploy/term_backend",
                             shell=True)
    time.sleep(2)

    try:
        subprocess.run(f"python3 pyterm.py -ts 19021",
                       cwd="tools/deploy/term_backend",
                       shell=True,
                       check=True)
    finally:
        jlink.kill()

def main(mote: str, mote_type: str):
    if mote_type == "zolertia":
        subprocess.run(f"python3 pyterm.py -b 115200 -p {args.mote}",
                       cwd="tools/deploy/term_backend",
                       shell=True,
                       check=True)

    elif mote_type == "nRF52840":
        main_nrf52840(mote)

    else:
        raise RuntimeError(f"Unknown mote type {mote_type}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Terminal')
    parser.add_argument("mote", help="The mote to open a terminal for.")
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], default="zolertia", help="The type of mote.")

    args = parser.parse_args()

    main(args.mote, args.mote_type)
