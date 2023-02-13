from pathlib import Path

import pynrfjprog.HighLevel

def get_com_ports_for_mote(node_id: str) -> list:
    node_id = int(node_id)

    with pynrfjprog.HighLevel.API() as api:
        with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
            probe_info = probe.get_probe_info()
            return [com_port.path for com_port in probe_info.com_ports]

def get_usb_dev_for_mote(node_id: str) -> str:
    com_ports = get_com_ports_for_mote(node_id)

    # Remove leading "/dev/"
    com_ports = [com_port.removeprefix("/dev/") for com_port in com_ports]

    usbs = list(Path("/sys/bus/usb/devices/").rglob("usb*"))

    for usb in usbs:
        usb_devs = list(usb.rglob("dev"))

        if any(com_port in str(usb_dev_path)
               for com_port in com_ports
               for usb_dev_path in usb_devs
              ):
            return usb

    raise RuntimeError(f"Unable to find usb for {node_id}")
