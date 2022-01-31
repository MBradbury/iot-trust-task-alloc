#!/usr/bin/env python3
import subprocess
import os

def main(mote_type: str):
    if mote_type == "zolertia":
        subprocess.run("motelist-zolertia",
                       cwd="tools/deploy/motelist_backend",
                       shell=True,
                       check=True)

    elif mote_type == "nRF52840":
        subprocess.run("python3 motelist_nrf.py",
                       cwd="tools/deploy/motelist_backend",
                       shell=True,
                       check=True)

    else:
        raise RuntimeError(f"Unknown mote type {mote_type}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Motelist')
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], default="zolertia", help="The type of mote.")

    args = parser.parse_args()

    main(args.mote_type)
