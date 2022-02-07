import pynrfjprog.HighLevel

def get_com_ports_for_mote(node_id: str) -> int:
    node_id = int(node_id)

    with pynrfjprog.HighLevel.API() as api:
        with pynrfjprog.HighLevel.DebugProbe(api, node_id) as probe:
            probe_info = probe.get_probe_info()
            return [com_port.path for com_port in probe_info.com_ports]
