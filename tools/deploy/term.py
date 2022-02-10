#!/usr/bin/env python3
import subprocess
import pathlib
import time
import sys

from typing import Optional

def main_pyterm_serial(mote: str, baud: int=115200, log_dir: Optional[pathlib.Path]=None):
    pyterm_log_dir = f"--log-dir-name {log_dir}" if log_dir is not None else ""
    pyterm_args = f"--format '' --prompt '' --no-intro {pyterm_log_dir}"

    command = f"python3 tools/deploy/term_backend/pyterm.py -b {baud} -p {mote} {pyterm_args}"
    print(command, flush=True)
    subprocess.run(command,
                   shell=True,
                   check=True,
                   stdin=sys.stdin)

def main_nrf(mote: str, device_type: str, speed="auto", log_dir: Optional[pathlib.Path]=None):
    # See: https://github.com/RIOT-OS/RIOT/blob/73ccd1e2e721bee38f958f8906ac32e5e1fceb0c/dist/tools/jlink/jlink.sh#L268

    JLINK_DIR = pathlib.Path("/opt/SEGGER/JLink")
    JLINK_EXE = JLINK_DIR / "JLinkExe"

    # https://wiki.segger.com/RTT#TELNET_channel_of_J-Link_software
    RTT_telnet_port = 19021

    opts = {
        "-nogui": 1,
        "-exitonerror": 1,
        "-device": device_type,
        "-speed": speed,
        "-if": "swd",
        "-jtagconf": "-1,-1",
        "-SelectEmuBySN": mote,
        "-RTTTelnetPort": RTT_telnet_port,
        "-AutoConnect": 1,
    }

    if log_dir is not None:
        opts["-log"] = log_dir / "JLinkExe.log"

    opts_str = " ".join(f"{k} {v}" for (k, v) in opts.items())

    jlink = subprocess.Popen(f"{JLINK_EXE} {opts_str} -CommanderScript tools/deploy/term_backend/jlink_term.seg",
                             shell=True)
    time.sleep(0.1)

    try:
        pyterm_log_dir = f"--log-dir-name {log_dir}" if log_dir is not None else ""
        pyterm_args = f"--format '' --prompt '' --no-intro {pyterm_log_dir}"

        subprocess.run(f"python3 tools/deploy/term_backend/pyterm.py --tcp-serial localhost:{RTT_telnet_port} {pyterm_args}",
                       shell=True,
                       check=True,
                       stdin=sys.stdin)
    finally:
        jlink.kill()

def main(mote: str, mote_type: str, log_dir: Optional[pathlib.Path]):
    if mote_type == "zolertia":
        main_pyterm_serial(mote, log_dir=log_dir)

    elif mote_type == "nRF52840":
        # Some different options for how to send/receive log output from nrf52840

        # 1. Use the serial terminal
        from tools.deploy.motedev_backend.nrf import get_com_ports_for_mote
        com_ports = get_com_ports_for_mote(mote)

        # For baud, see: arch/cpu/nrf52840/nrf52840-conf.h
        main_pyterm_serial(com_ports[0], baud=115200, log_dir=log_dir)

        # 2. Use RTT via JLinkExe
        # See: Section 4.8.2.2.1 of https://infocenter.nordicsemi.com/pdf/nRF52840_PS_v1.0.pdf
        # Maximum speed of SWD is 8 MHz
        #main_nrf(mote, "nRF52840_xxAA", speed=8000, log_dir=log_dir)

        # 3. Use RTT via custom RTT reader/writer
        #from tools.deploy.term_backend.nrf import term_nrf
        #term_nrf(int(mote))

    else:
        raise RuntimeError(f"Unknown mote type {mote_type}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Terminal')
    parser.add_argument("mote", help="The mote to open a terminal for.")
    parser.add_argument("mote_type", choices=["zolertia", "nRF52840"], help="The type of mote.")
    parser.add_argument("--log-dir", default=None, type=pathlib.Path, help="The directory to output logs to.")
    args = parser.parse_args()

    main(args.mote, args.mote_type, args.log_dir)
