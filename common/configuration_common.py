from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address

class DeviceKind(Enum):
    NRF52840 = "nRF52840"
    ZOLERTIA = "zolertia"

@dataclass
class Device:
    hostname: str
    identifier: int
    eui64: str
    kind: DeviceKind

root_ipv6_addr = IPv6Address("fd00::1")
