#!/usr/bin/env python3
import subprocess
import os

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Motelist')
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], default="zolertia", help="The type of mote.")

    args = parser.parse_args()

    if args.mote_type == "zolertia":
        subprocess.run("motelist-zolertia",
                       cwd="tools/deploy/motelist_backend",
                       shell=True,
                       check=True)

    elif args.mote_type == "nRF52840":
        subprocess.run("motelist.py",
                       cwd=os.path.expanduser("~/bin/motelist"),
                       shell=True,
                       check=True)

    else:
        raise RuntimeError(f"Unknown mote type {args.mote_type}")
