#!/usr/bin/env python3

import subprocess
import pathlib

from typing import Optional

def config_nrf(mote: str, device_type: str, speed="auto", log_dir: Optional[pathlib.Path]=None):
    # nrf need to have mass storage disabled in order to support receiving more
    # than 64 bytes over uart
    # This script disables mass storage
    # powers off the target sleeps for a bit and then powers it back on
    # See: https://github.com/openthread/openthread/issues/2857

    JLINK_DIR = pathlib.Path("/opt/SEGGER/JLink")
    JLINK_EXE = JLINK_DIR / "JLinkExe"

    opts = {
        "-nogui": 1,
        "-exitonerror": 1,
        "-device": device_type,
        "-speed": speed,
        "-if": "swd",
        "-jtagconf": "-1,-1",
        "-SelectEmuBySN": mote,
        "-AutoConnect": 1,
        "-CommanderScript": "tools/deploy/config_backend/msddisable.seg"
    }

    if log_dir is not None:
        opts["-log"] = log_dir / "JLinkExe-configure.log"

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    subprocess.run(f"{JLINK_EXE} {opts_str}",
                   shell=True)

    # TODO: Need to toggle power to the usb port that this device is connected to

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Configure nrf.')
    parser.add_argument("mote", help="The mote to configure")
    parser.add_argument("--log-dir", default=None, type=pathlib.Path, help="The directory to output logs to.")
    args = parser.parse_args()

    config_nrf(args.mote, "nRF52840_xxAA", speed=8000, log_dir=args.log_dir)
