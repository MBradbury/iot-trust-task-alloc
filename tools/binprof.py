#!/usr/bin/env python3

import subprocess
from dataclasses import dataclass
from typing import Optional
from pprint import pprint
from collections import defaultdict

import argparse

# Details of what the bufferent `symbol_type`s mean
# https://sourceware.org/binutils/docs/binutils/nm.html

# This article hit the same problem with nm
# https://web.archive.org/web/20190317203555/https://www.embeddedrelated.com/showarticle/900.php
# They looked up details with readelf/objdump

parser = argparse.ArgumentParser(description='RAM and Flash profiling')
parser.add_argument('binary', type=str, help='The path to the binary to profile')
parser.add_argument('--other', type=str, default="other", help='What to classify unknown memory as')
parser.add_argument('--no-error-if-unknown', action='store_true', default=False, help='Raise an error if there is memory classified as other')
args = parser.parse_args()

result = subprocess.run(
    f"nm --print-size --size-sort --radix=d --line-numbers {args.binary}",
    check=True,
    shell=True,
    capture_output=True,
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
    elif r.symbol_type in "Nn":
        # Debug symbol
        pass
    else:
        raise RuntimeError(f"Unknown symbol type {r}")

def summarise(symbs):
    return sum(x.size for x in symbs)

def classify(symb, other="other"):
    # I apologise for this horrible function.
    # nm is unable to pick up the correct location of static variables declared inside functions
    # So we need to manually classify these variables
    # Other variables simply do not have a location for some unknown reason

    if symb.location is None:
        if symb.name in ("process_current", "process_list", "curr_instance", "linkaddr_null",
                         "linkaddr_node_addr", "etimer_process", "csma_driver", "drop_route", "framer_802154"):
            return "contiki-ng/net"
        if symb.name.startswith(("uip", "sicslowpan_", "rpl_", "tcpip_", "root_ipaddr.")):
            return "contiki-ng/net"

        if symb.name in ("serial_line_process", "sensors_process", "serial_line_event_message",
                         "curr_log_level_main", "curr_log_level_coap", "button_hal_periodic_event",
                         "button_hal_press_event", "button_hal_release_event", "node_id", "sensors_event",
                         "aes_128_driver", "ccm_star_driver"):
            return "contiki-ng"
        if symb.name.startswith(("heap_end.",)):
            return "contiki-ng"
        if symb.name.startswith("p05."): # I think this refers to MP3_WTV020SD_P05_PORT
            return "contiki-ng"

        if symb.name in ("bignum_add_get_result", "ecc_add_get_result", "vdd3_sensor", "vectors"):
            return "contiki-ng/cc2538"
        if symb.name.startswith("cc2538_"):
            return "contiki-ng/cc2538"
        if symb.name.startswith("reset_cause."):
            return "contiki-ng/cc2538"

        if any(symb.name.startswith(x) for x in ("nrf52840", "CSWTCH")):
            return "contiki-ng/nrf52840"
        if symb.name in ("_SEGGER_RTT", "SystemCoreClock", "__malloc_free_list", "__malloc_sbrk_start",
                         "_global_atexit", "m_irr_sem", "__sf_fake_stderr", "__sf_fake_stdin",
                         "__sf_fake_stdout", "temperature_sensor", "regTemps", "_global_impure_ptr"):
            return "contiki-ng/nrf52840"
        if symb.name in ("completed.8100", "use_count", "object.8105"):
            return "contiki-ng/nrf52840"

        if any(symb.name.startswith(x) for x in ("ssi_ecpki", "CRYS", "SaSi", "sasi", "Pka",
                                                 "pSaSi", "CRYPTOCELL", "LLF", "HASH_LARVAL_",
                                                 "_DX_ECPKI", "Pki", "ecpki", "g_nrf_crypto")):
            return "contiki-ng/nrf52840/crypto"
        if symb.name in ("g_cc310_mutex",):
            return "contiki-ng/nrf52840/crypto"
        if symb.name in ('_aInitStr.5719', 'pow10.5210', 'ProcessBypass'):
            return "contiki-ng/nrf52840/crypto"
        if symb.name in ('ecDomainsFuncP', 'InitSwHash512', 'EcWrstDsaTruncateMsg',
                         'InitHash', 'EcWrstFullCheckPublKey', 'RNG_PLAT_SetUserRngParameters',
                         'EcWrstDhDeriveSharedSecret', 'FinishHash', 'HASH_COMMON_IncMsbUnsignedCounter',
                         'ProcessSwHash512', 'InitAes.part.0', 'EcWrstDsaVerify', 'FinishSwHash512',
                         'startTrngHW', 'EcWrstInitPubKey', '_DX_ECDSA_SignFinish', 'ProcessAes',
                         'ProcessHash', 'FinalizeAes', 'getTrngSource', 'K512', 'DoubleMdf2Mdf',
                         'EcWrstDsaSign'):
            return "contiki-ng/nrf52840/crypto"

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
        if symb.name in ("pe_data_from_resource_rich_node", "resource_rich_edge_started",
                         "applications_available", "application_names"): # Edge specific
            return "system/common"

        if symb.name in ("_C_numeric_locale", "__mprec_bigtens", "__mprec_tinytens", "__mprec_tens",
                         "__hexdig", "_ctype_", "_impure_ptr"):
            return "newlib"
        if symb.name.startswith(("fpinan.", "fpi.")):
            return "newlib"

        return other

    if "common/mqtt-over-coap" in symb.location:
        return "system/mqtt-over-coap"

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

    if "arch/cpu/nrf52840" in symb.location or "arch/platform/nrf52840" in symb.location:
        return "contiki-ng/nrf52840"

    if "applications/monitoring" in symb.location:
        return "applications/monitoring"
    if "applications/routing" in symb.location:
        return "applications/routing"
    if "applications/challenge-response" in symb.location:
        return "applications/challenge-resp"

    if any(osdir in symb.location for osdir in ("os/lib", "os/sys", "os/dev", "os/contiki")):
        return "contiki-ng"

    if "common/crypto" in symb.location:
        return "system/crypto"

    if "common/trust" in symb.location:
        return "system/trust"

    if "wsn/node" in symb.location or "wsn/edge" in symb.location:
        return "system/common"

    return other


def classify_all(symbs, other="other"):
    result = defaultdict(list)

    for symb in symbs:
        result[classify(symb, other=other)].append(symb)

    return dict(result)

classified_ram_symb = classify_all(ram_symb, other=args.other)
summarised_ram_symb = {k: summarise(v) for k, v in classified_ram_symb.items()}

classified_flash_symb = classify_all(flash_symb, other=args.other)
summarised_flash_symb = {k: summarise(v) for k, v in classified_flash_symb.items()}

if "other" in classified_ram_symb or "other" in classified_flash_symb:
    try:
        print("RAM unknown:")
        pprint(classified_ram_symb["other"])
    except KeyError:
        pass

    try:
        print("Flash unknown:")
        pprint(classified_flash_symb["other"])
    except KeyError:
        pass

    if not args.no_error_if_unknown:
        raise RuntimeError("Symbols with an unknown classification")

total_flash_symb = sum(summarised_flash_symb.values())
total_ram_symb = sum(summarised_ram_symb.values())

keys = set(summarised_ram_symb.keys()) | set(classified_flash_symb.keys())
for k in sorted(keys):
    k_sum_flash = summarised_flash_symb.get(k, 0)
    k_sum_flash_pc = round(100*k_sum_flash/total_flash_symb, 1)

    k_sum_ram = summarised_ram_symb.get(k, 0)
    k_sum_ram_pc = round(100*k_sum_ram/total_ram_symb, 1)

    print(f"{k} & {k_sum_flash} & {k_sum_flash_pc} & {k_sum_ram} & {k_sum_ram_pc} \\\\")
print("\\midrule")
print(f"Total Used & {total_flash_symb} & 100 & {total_ram_symb} & 100 \\\\")
print()

config = [
    ('Certificates', 'PUBLIC_KEYSTORE_SIZE', 12, 'public_keys_memb'),
    ('Stereotypes', 'MAX_NUM_STEREOTYPES', 5, 'stereotypes_memb'),
    ('Edges', 'NUM_EDGE_RESOURCES', 4, 'edge_resources_memb'),
    ('Edge Capabilities', 'NUM_EDGE_CAPABILITIES', 3 * 4, 'edge_capabilities_memb'),
    ('Peers', 'NUM_PEERS', 8, 'peers_memb'),
    ('Peer Edges', 'NUM_PEERS', 8 * 4, 'peer_edges_memb'),
    ('Peer Edge Capabilities', 'NUM_PEERS', 8 * 4 * 3, 'peer_capabilities_memb'),
    None,
    ('Reputation Tx Buffer', 'TRUST_TX_SIZE', 2, 'trust_tx_memb'),
    ('Reputation Rx Buffer', 'TRUST_RX_SIZE', 2, 'trust_rx_memb'),
    None,
    ('Sign Buffer', 'MESSAGES_TO_SIGN_SIZE', 3, 'messages_to_sign_memb'),
    ('Verify Buffer', 'MESSAGES_TO_VERIFY_SIZE', 3, 'messages_to_verify_memb'),
]

for conf in config:
    if conf is None:
        print("\\midrule")
        continue

    (nice_name, cname, num, vname) = conf
    try:
        [symb] = [x for x in ram_symb if x.name == vname + "_memb_mem"]
        size = symb.size
        print(f"{nice_name} & {num} & {int(size/num)} & {size} \\\\ % {vname}")
    except ValueError:
        print(f"Missing {vname}")
