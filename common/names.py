import common.configuration as conf
from tools.keygen.util import ip_to_eui64

from ipaddress import IPv6Address

def hostname_to_name(hostname: str) -> str:
    return conf.hostname_to_names[hostname]

def ip_to_name(ip: IPv6Address) -> str:
    (hostname,) = [k for (k, v) in conf.hostname_to_ips.items() if v == ip]
    return conf.hostname_to_names[hostname]

def eui64_to_name(eui64: str) -> str:
    (hostname,) = [k for (k, v) in conf.hostname_to_ips.items() if ip_to_eui64(v).hex() == eui64]
    return conf.hostname_to_names[hostname]
