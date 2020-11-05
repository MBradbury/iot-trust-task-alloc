#!/usr/bin/env python

import subprocess
from dataclasses import dataclass
from typing import Optional
from pprint import pprint
from collections import defaultdict

# Details of what the bufferent `symbol_type`s mean
# https://sourceware.org/binutils/docs/binutils/nm.html

# This article hit the same problem with nm
# https://web.archive.org/web/20190317203555/https://www.embeddedrelated.com/showarticle/900.php
# They looked up details with readelf/objdump

"""subprocess.run(
    "make distclean TRUST_MODEL=basic TRUST_CHOOSE=banded",
    check=True,
    shell=True,
    cwd="wsn/node",
)"""
"""subprocess.run(
    "make node TRUST_MODEL=basic TRUST_CHOOSE=banded",
    check=True,
    shell=True,
    cwd="wsn/node",
)"""

result = subprocess.run(
    "nm --print-size --size-sort --radix=d --line-numbers node.zoul",
    check=True,
    shell=True,
    capture_output=True,
    cwd="wsn/node",
    encoding="utf-8",
    universal_newlines=True,
)

@dataclass(frozen=True)
class Result:
    position: int
    size: int
    symbol_type: str
    name: str
    location: Optional[str] = None

    def __post_init__(self):
        super().__setattr__("position", int(self.position))
        super().__setattr__("size", int(self.size))

flash_symb = []
ram_symb = []

for line in result.stdout.split("\n"):
    if not line:
        continue

    details = line.split(' ')

    if "\t" in details[-1]:
        details = details[:-1] + details[-1].split("\t")

    r = Result(*details)

    # Contiki's ramprof picks up [abdrw] and flashprof picks up [t] (both case insensitive)

    if r.symbol_type in "Tt":
        flash_symb.append(r)
    elif r.symbol_type in "abdrwABDRW":
        ram_symb.append(r)
    else:
        raise RuntimeError(f"Unknown symbol type {r.symbol_type}")

def summarise(symbs):
    return sum(x.size for x in symbs)

#print("text", summarise(flash_symb))
#print("data", summarise(ram_symb))

def classify(symb, other="other"):
    if symb.location is None:
        if symb.name in ("process_current", "process_list", "curr_instance", "linkaddr_null",
                         "linkaddr_node_addr", "etimer_process", "csma_driver", "drop_route", "framer_802154"):
            return "contiki-ng/net"
        if symb.name.startswith(("uip", "sicslowpan_", "rpl_", "tcpip_", "root_ipaddr.")):
            return "contiki-ng/net"

        if symb.name in ("serial_line_process", "sensors_process", "serial_line_event_message",
                         "curr_log_level_main", "curr_log_level_coap", "button_hal_periodic_event",
                         "button_hal_press_event", "button_hal_release_event", "node_id", "sensors_event"):
            return "contiki-ng"
        if symb.name.startswith(("heap_end.",)):
            return "contiki-ng"

        if symb.name in ("bignum_add_get_result", "ecc_add_get_result", "vdd3_sensor", "vectors"):
            return "contiki-ng/cc2538"
        if symb.name.startswith("cc2538_"):
            return "contiki-ng/cc2538"
        if symb.name.startswith("reset_cause."):
            return "contiki-ng/cc2538"

        if symb.name in ("coap_status_code", "coap_error_message", "coap_timer_default_driver"):
            return "contiki-ng/coap"
        if symb.name.startswith(("message.", "response.")):
            return "contiki-ng/coap"

        if symb.name in ("pe_edge_capability_add", "pe_edge_capability_remove"):
            return "system/trust"

        if symb.name in ("pe_message_signed", "pe_message_signed", "pe_message_verified",
                         "root_cert", "our_cert", "our_privkey"):
            return "system/crypto"
        if symb.name.startswith(("verify_state.", "sign_state.", "ecdh2_unver_state.", "ecdh2_req_state.",
                                 "pkitem.", "sitem.", "vitem.")):
            return "system/crypto"

        if symb.name in ("mqtt_client_process"):
            return "system/mqtt-over-coap"

        if symb.name in ("pe_timed_unlock_unlocked", "root_ep", "autostart_processes"):
            return "system/common"

        if symb.name in ("_C_numeric_locale", "__mprec_bigtens", "__mprec_tinytens", "__mprec_tens",
                         "__hexdig", "_ctype_", "_impure_ptr"):
            return "newlib"
        if symb.name.startswith(("fpinan.", "fpi.")):
            return "newlib"

        return other

    if "newlib" in symb.location or "libgcc" in symb.location:
        return "newlib"

    if "oscore" in symb.location:
        return "contiki-ng/oscore"

    if "os/net/app-layer/coap" in symb.location:
        return "contiki-ng/coap"

    if "os/net" in symb.location:
        return "contiki-ng/net"

    if "arch/cpu/cc2538" in symb.location or "arch/platform/zoul" in symb.location:
        return "contiki-ng/cc2538"

    if "applications/monitoring" in symb.location:
        return "applications/monitoring"
    if "applications/routing" in symb.location:
        return "applications/routing"
    if "applications/challenge-response" in symb.location:
        return "applications/challenge-resp"

    if any(osdir in symb.location for osdir in ("os/lib", "os/sys", "os/dev", "os/contiki")):
        return "contiki-ng"

    if "crypto" in symb.location:
        return "system/crypto"

    if "trust" in symb.location:
        return "system/trust"

    if "mqtt-over-coap" in symb.location:
        return "system/mqtt-over-coap"

    if "wsn/node" in symb.location or "wsn/edge" in symb.location:
        return "system/common"

    return other


def classify_all(symbs, other="other"):
    result = defaultdict(list)

    for symb in symbs:
        result[classify(symb, other=other)].append(symb)

    return dict(result)

other = "contiki-ng"
#other = "other"

classified_ram_symb = classify_all(ram_symb, other=other)

#pprint(classified_ram_symb)
try:
    pprint(classified_ram_symb["other"])
except KeyError:
    pass

summarised_ram_symb = {k: summarise(v) for k, v in classified_ram_symb.items()}
#pprint(summarised_ram_symb)



classified_flash_symb = classify_all(flash_symb, other=other)

#print(classified_flash_symb)
try:
    pprint(classified_flash_symb["other"])
except KeyError:
    pass

summarised_flash_symb = {k: summarise(v) for k, v in classified_flash_symb.items()}
#pprint(summarised_flash_symb)

total_flash_symb = sum(summarised_flash_symb.values())
total_ram_symb = sum(summarised_ram_symb.values())


keys = set(summarised_ram_symb.keys()) | set(classified_flash_symb.keys())


for k in sorted(keys):
    print(f"{k} & {summarised_flash_symb[k]} & {round(100*summarised_flash_symb[k]/total_flash_symb, 1)} & {summarised_ram_symb[k]} & {round(100*summarised_ram_symb[k]/total_ram_symb, 1)} \\\\")
print("\\midrule")
print(f"Total Used & {total_flash_symb} & & {total_ram_symb} & \\\\")


"""result = subprocess.run(
    "size node.zoul",
    check=True,
    shell=True,
    capture_output=True,
    cwd="wsn/node",
    encoding="utf-8",
    universal_newlines=True,
)
size_output = [[x.strip() for x in line.split("\t")] for line in result.stdout.split("\n") if line]

size_output = dict(zip(*size_output))

print(size_output)

print(f"Total Used (size) & {size_output['text']} & {int(size_output['data']) + int(size_output['bss'])} \\\\")
"""


config = [
    ('Certificates', 'PUBLIC_KEYSTORE_SIZE', 12, 'public_keys_memb'),
    ('Reputation Tx Buffer', 'TRUST_TX_SIZE', 2, 'trust_tx_memb'),
    ('Reputation Rx Buffer', 'TRUST_RX_SIZE', 2, 'trust_rx_memb'),
    ('Stereotypes', 'MAX_NUM_STEREOTYPES', 5, 'stereotypes_memb'),
    ('Edges', 'NUM_EDGE_RESOURCES', 4, 'edge_resources_memb'),
    ('Edge Capabilities', 'NUM_EDGE_CAPABILITIES', 3 * 4, 'edge_capabilities_memb'),
    ('Peers', 'NUM_PEERS', 8, 'peers_memb'),
    ('Peer Edges', 'NUM_PEERS', 8 * 4, 'peer_edges_memb'),
    ('Peer Edge Capabilities', 'NUM_PEERS', 8 * 4 * 3, 'peer_capabilities_memb'),
]

for (nice_name, cname, num, vname) in config:
    symb = next(x for x in ram_symb if x.name == vname + "_memb_mem")
    size = symb.size
    print(f"{nice_name} & {num} & {int(size/num)} & {size} \\\\ % {vname}")

#pprint(ram_symb)
