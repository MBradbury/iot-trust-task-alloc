from __future__ import annotations

import ipaddress

def ip_to_eui64(subject: Union[ipaddress.IPv6Address,str], root_ip: Union[ipaddress.IPv6Address,str]="fd00::1") -> bytes:
    subject = ipaddress.IPv6Address(subject)
    root_ip = ipaddress.IPv6Address(root_ip)

    # Last 8 bytes of the ip address
    eui64 = bytearray(int(subject).to_bytes(16, byteorder='big')[-8:])

    # See: uip_ds6_set_lladdr_from_iid
    if subject != root_ip:
        eui64[0] ^= 0x02

    return bytes(eui64)
