import ipaddress

def ip_to_eui64(subject: str, root_ip: str="fd00::1") -> bytes:
    ip = ipaddress.ip_address(subject)

    # Last 8 bytes of the ip address
    eui64 = bytearray(int(ip).to_bytes(16, byteorder='big')[-8:])

    # See: uip_ds6_set_lladdr_from_iid
    if subject != root_ip:
        eui64[0] ^= 0x02

    return bytes(eui64)
