#!/usr/bin/env python3

def nRF52840_config(mote, **kwargs):
    from tools.deploy.config_backend.nrf import config_nrf
    config_nrf(mote, "nRF52840_xxAA", speed=8000)

def config(mote, mote_type):
    if mote_type == "zolertia":
        pass
    elif mote_type == "nRF52840":
        return nRF52840_config(mote)
    else:
        raise NotImplementedError(f"Support for configuring {mote_type} has not been implemented")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to sensor nodes.')
    parser.add_argument("mote", help="The device identifier to flash.")
    parser.add_argument("mote_type", choices=["zolertia", "nRF52840"], help="The type of mote.")
    args = parser.parse_args()

    config(args.mote, args.mote_type)
