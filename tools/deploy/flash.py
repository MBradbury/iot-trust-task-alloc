#!/usr/bin/env python3
import subprocess

def cc2538_flash(mote, filename, target_addr=None, **kwargs):
    """
    Flash firmware for Zolertia RE-Motes (CC2538-Based)

    Args:
        mote (str): port to flash to
        filename (str): filename of firmware file
        target_addr (str): start address for flashing (Contiki starts from 
            address 0x00202000 on this platform)

    Returns:
        Return code of flashing process
    """
    args = [f"-p {mote}"]

    if target_addr is not None:
        args.append(f"-a {target_addr}")

    cmd = f'cc2538-bsl.py -e -w -v -b 460800 {" ".join(args)} {filename}'

    subprocess.run(cmd, cwd="tools/deploy/flash_backend", shell=True, check=True)

def nRF52840_flash(mote, filename, **kwargs):
    from flash_backend.nrf import flash_nrf

    flash_nrf(filename, mote)

def flash(mote, filename, mote_type, firmware_type):
    """
    Call the appropriate flashing function with the correct arguments 
    for the given firmware and mote

    Args:
        mote (str): port to flash to
        filename (str): filename of firmware file
        mote_type (str): zolertia or telosb
        firmware_type (str): contiki or riot
    
    Raises:
        NotImplementedError: unsupported mote-OS combination
        RuntimeError: unrecognised firmware OS
    """
    kwargs = {}

    if firmware_type == "contiki" and mote_type == "zolertia":
        kwargs["target_addr"] = "0x00202000"

    if mote_type == "zolertia":
        return cc2538_flash(mote, filename, **kwargs)
    elif mote_type == "nRF52840":
        return nRF52840_flash(mote, filename)
    else:
        raise NotImplementedError(f"Support for flashing {mote_type} for {firmware_type} has not been implemented")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Flash firmware to sensor nodes.')
    parser.add_argument("mote", help="The device identifier to flash.")
    parser.add_argument("filename", help="The path to the binary to flash.")
    parser.add_argument("mote_type", choices=["zolertia", "nRF52840"], help="The type of mote.")
    parser.add_argument("firmware_type", choices=["contiki", "riot"], help="The OS that was used to create the firmware.")

    args = parser.parse_args()

    flash(args.mote, args.filename, args.mote_type, args.firmware_type)
