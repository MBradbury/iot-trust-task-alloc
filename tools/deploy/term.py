#!/usr/bin/env python3
import subprocess
import pathlib
import time

from typing import Optional

import pynrfjprog.HighLevel
import pynrfjprog.APIError

def main_zolertia(mote: str, log_dir: Optional[pathlib.Path]):
    subprocess.run(f"python3 pyterm.py -b 115200 -p {args.mote}",
                   cwd="tools/deploy/term_backend",
                   shell=True,
                   check=True)

def get_serial_number_for_mote(mote: str) -> int:
    with pynrfjprog.HighLevel.API() as api:
        for node_id in api.get_connected_probes():
            with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
                probe_info = probe.get_probe_info()
                
                if mote in [com_port.path for com_port in probe_info.com_ports]:
                    return node_id

    raise RuntimeError(f"Unable to find serial number for mote {mote}")

def main_nrf52840(mote: str, log_dir: Optional[pathlib.Path]):
    # See: https://github.com/RIOT-OS/RIOT/blob/73ccd1e2e721bee38f958f8906ac32e5e1fceb0c/dist/tools/jlink/jlink.sh#L268

    JLINK_DIR = pathlib.Path("/opt/SEGGER/JLink")
    JLINK_EXE = JLINK_DIR / "JLinkExe"

    # https://wiki.segger.com/RTT#TELNET_channel_of_J-Link_software
    RTT_telnet_port = 19021

    opts = {
        "-nogui": 1,
        "-exitonerror": 1,
        "-device": "nRF52840_xxAA", # From ExpDevList from JLinkExe
        "-speed": 2000,
        "-if": "swd",
        "-jtagconf": "-1,-1",
        "-SelectEmuBySN": get_serial_number_for_mote(mote),
        "-RTTTelnetPort": RTT_telnet_port,
        "-AutoConnect": 1,
    }

    if log_dir is not None:
        opts["-log"] = log_dir / "JLinkExe.log"

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    jlink = subprocess.Popen(f"{JLINK_EXE} {opts_str} -CommanderScript jlink_term.seg",
                             cwd="tools/deploy/term_backend",
                             shell=True)
    time.sleep(2)

    try:
        subprocess.run(f"python3 pyterm.py --tcp-serial localhost:{RTT_telnet_port}",
                       cwd="tools/deploy/term_backend",
                       shell=True,
                       check=True)
    finally:
        jlink.kill()

def main(mote: str, mote_type: str, log_dir: Optional[pathlib.Path]):
    if mote_type == "zolertia":
        main_zolertia(mote, log_dir)

    elif mote_type == "nRF52840":
        main_nrf52840(mote, log_dir)

    else:
        raise RuntimeError(f"Unknown mote type {mote_type}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Terminal')
    parser.add_argument("mote", help="The mote to open a terminal for.")
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], default="zolertia", help="The type of mote.")
    parser.add_argument("--log-dir", default=None, type=pathlib.Path, help="The directory to output logs to.")

    args = parser.parse_args()

    main(args.mote, args.mote_type, args.log_dir)
