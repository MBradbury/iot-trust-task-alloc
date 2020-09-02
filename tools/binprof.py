#!/usr/bin/env python

import subprocess
from dataclasses import dataclass
from typing import Optional
from pprint import pprint
from collections import defaultdict

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

tsymb = []
dsymb = []

for line in result.stdout.split("\n"):
    if not line:
        continue

    details = line.split(' ')

    if "\t" in details[-1]:
        details = details[:-1] + details[-1].split("\t")

    r = Result(*details)

    if r.symbol_type in ("T", "t"):
        tsymb.append(r)
    else:
        dsymb.append(r)

def summarise(symbs):
    return sum(x.size for x in symbs)

#print("text", summarise(tsymb))
#print("data", summarise(dsymb))

def classify(symb):
    if symb.location is None:
        if symb.name in ("process_current", "process_list",
                         "curr_instance", "linkaddr_node_addr", "etimer_process"):
            return "contiki/net"
        if (symb.name.startswith("uip") or symb.name.startswith("sicslowpan_") or
            symb.name.startswith("rpl_") or symb.name.startswith("tcpip_")):
            return "contiki/net"

        if symb.name in ("serial_line_process", "sensors_process", "serial_line_event_message",
                         "curr_log_level_main", "curr_log_level_coap", "button_hal_periodic_event",
                         "button_hal_press_event", "button_hal_release_event", "node_id", "sensors_event"):
            return "contiki"

        if symb.name in ("bignum_add_get_result", "ecc_add_get_result", "vdd3_sensor"):
            return "contiki/cc2538"
        if symb.name.startswith("cc2538_"):
            return "contiki/cc2538"

        if symb.name in ("coap_status_code", "coap_error_message"):
            return "contiki/coap"

        if symb.name in ("pe_edge_capability_add", "pe_edge_capability_remove"):
            return "petras/trust"

        if symb.name in ("pe_message_signed", "pe_message_signed", "pe_message_verified", "root_key", "our_key"):
            return "petras/crypto"

        if symb.name in ("mqtt_client_process"):
            return "petras/mqtt-over-coap"

        if symb.name in ("pe_timed_unlock_unlocked", "root_ep"):
            return "petras/common"

        return "other"

    if "newlib" in symb.location or "libgcc" in symb.location:
        return "newlib"

    if "oscore" in symb.location:
        return "contiki/oscore"

    if "os/net/app-layer/coap" in symb.location:
        return "contiki/coap"

    if "os/net" in symb.location:
        return "contiki/net"

    if "arch/cpu/cc2538" in symb.location or "arch/platform/zoul" in symb.location:
        return "contiki/cc2538"

    if "applications/monitoring" in symb.location:
        return "applications/monitoring"
    if "applications/routing" in symb.location:
        return "applications/routing"
    if "applications/challenge-response" in symb.location:
        return "applications/challenge-response"

    if any(osdir in symb.location for osdir in ("os/lib", "os/sys", "os/dev", "os/contiki")):
        return "contiki"

    if "crypto" in symb.location:
        return "petras/crypto"

    if "trust" in symb.location:
        return "petras/trust"

    if "mqtt-over-coap" in symb.location:
        return "petras/mqtt-over-coap"

    if "wsn/node" in symb.location or "wsn/edge" in symb.location:
        return "petras/common"

    return "other"


def classify_all(symbs):
    result = defaultdict(list)

    for symb in symbs:
        result[classify(symb)].append(symb)

    return result

csymb = classify_all(dsymb)

pprint(csymb)
pprint(csymb["other"])

ssymb = {k: summarise(v) for k, v in csymb.items()}
pprint(ssymb)



ctsymb = classify_all(tsymb)

pprint(ctsymb)
pprint(ctsymb["other"])

stsymb = {k: summarise(v) for k, v in ctsymb.items()}
pprint(stsymb)



keys = set(ssymb.keys()) | set(ctsymb.keys())


for k in sorted(keys):
    print(f"{k} & {stsymb[k]} & {ssymb[k]} \\\\")
print("\\midrule")
print(f"Total Used & {sum(stsymb.values())} & {sum(ssymb.values())} \\\\")
