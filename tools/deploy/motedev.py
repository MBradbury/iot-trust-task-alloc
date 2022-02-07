#!/usr/bin/env python3
import subprocess
import os

def get_mote_device(device: str, mote_type: str) -> str:
    if mote_type == "zolertia":
        return device

    elif mote_type == "nRF52840":
        from tools.deploy.motedev_backend.nrf import get_com_ports_for_mote
        ports = get_com_ports_for_mote(device)
        return ports[0]

    else:
        raise RuntimeError(f"Unknown mote type {mote_type}")

def main(device: str, mote_type: str):
    print(get_mote_device(device, mote_type))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Get Mote Device')
    parser.add_argument("--device", required=True, help="The device identifier")
    parser.add_argument("--mote-type", choices=["zolertia", "nRF52840"], required=True, help="The type of mote.")

    args = parser.parse_args()

    main(args.device, args.mote_type)
