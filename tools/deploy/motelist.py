#!/usr/bin/env python3
import subprocess

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Motelist')
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], default="zolertia", help="The type of mote.")

    args = parser.parse_args()

    if args.mote_type == "zolertia":
        subprocess.check_output("motelist-zolertia",
                                cwd="tools/deploy/motelist_backend",
                                shell=True)

    elif args.mote_type == "nRF52840":
        raise NotImplementedError()

    else:
        raise RuntimeError(f"Unknown mote type {args.mote_type}")
