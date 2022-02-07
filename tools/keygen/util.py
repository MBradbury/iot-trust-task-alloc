from __future__ import annotations

from ipaddress import IPv6Address

def ip_to_eui64(subject: Union[IPv6Address,str], root_ip: Union[IPv6Address,str]="fd00::1") -> bytes:
    subject = IPv6Address(subject)
    root_ip = IPv6Address(root_ip)

    # Last 8 bytes of the ip address
    eui64 = bytearray(int(subject).to_bytes(16, byteorder='big')[-8:])

    # See: uip_ds6_set_lladdr_from_iid
    if subject != root_ip:
        eui64[0] ^= 0x02

    return bytes(eui64)

def eui64_to_ipv6(eui64: Union[str,bytes,bytearray]) -> IPv6Address:
    if isinstance(eui64, str):
        eui64 = bytearray.fromhex(eui64.replace(":", ""))
    else:
        eui64 = bytearray(eui64)

    # See: uip_ds6_set_lladdr_from_iid
    eui64[0] ^= 0x02

    return IPv6Address(b"\xfd\x00" + b"\x00"*6 + eui64)
