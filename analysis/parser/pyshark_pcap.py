#!/usr/bin/env python3

import glob
import os
from pprint import pprint
from collections import defaultdict
import ipaddress
import textwrap
#import json
import itertools

from resource_rich.root.keystore import Keystore

from common.configuration import hostname_to_ips

import pyshark

class PcapAnalyser:
    def __init__(self, hostname):
        self.hostname = hostname
        self.addr = hostname_to_ips[hostname]
        self.addrs = {self.addr, "fe80" + self.addr[4:], self.addr[4:]}

        eui64 = bytearray(int(ipaddress.IPv6Address(self.addr)).to_bytes(16, 'big')[8:])
        eui64[0] ^= 0x2

        self.eui64 = ':'.join(textwrap.wrap(bytes(eui64).hex(), 2))

        self.tx = defaultdict(list)
        self.rx = defaultdict(list)

        self.tx_addrs = set()
        self.rx_addrs = set()

        self.min_snift_time = None
        self.max_snift_time = None

        self.packet_kinds = {}

    def get_tx_rx_list(self, packet):
        try:
            addr = packet['6lowpan'].src
            is_tx = addr in self.addrs
        except AttributeError:
            addr = packet.wpan.src64
            is_tx = addr == self.eui64

        if is_tx:
            self.tx_addrs.add(addr)
            return self.tx
        else:
            self.rx_addrs.add(addr)
            return self.rx

    def _layer_matches_url(self, layer, uri):
        return getattr(layer, "opt_uri_path", "") in (uri, f'/{uri}') or \
               getattr(layer, "opt_uri_path_recon", "") in (uri, f'/{uri}')

    def _print_packet_attributes(self, packet, *layers):
        print(packet)
        for layer in layers:
            print(layer, {n: getattr(packet[layer], n) for n in packet[layer].field_names})

    def _record_type(self, packet, xx, kind):
        xx[kind].append(packet)

        self.packet_kinds[int(packet.number)] = kind
        
    def analyse(self, packets):
        #for (packet, kind, time) in packets:
        for packet in packets:
            # Skip IEEE 802.15.4 ACK packets
            if packet.wpan.frame_type.int_value == 0x2:
                continue

            ts = float(packet.sniff_timestamp)

            if self.min_snift_time is None or self.min_snift_time > ts:
                self.min_snift_time = ts

            if self.max_snift_time is None or self.max_snift_time < ts:
                self.max_snift_time = ts

            # Every packet from here should be 6lowpan
            if '6lowpan' not in packet:
                self._print_packet_attributes(packet)
                continue

            xx = self.get_tx_rx_list(packet)
            #yy = self.tx if kind == "tx" else self.rx

            #if xx is not yy:
            #    raise RuntimeError()

            # Network maintenance
            if 'ICMPv6' in packet:
                icmpv6_type = {
                    128: "ping-request",
                    129: "ping-reply",

                    155: "rpl-control",

                }[int(packet['ICMPv6'].type)]

                try:
                    self._record_type(packet, xx, icmpv6_type)
                except KeyError:
                    self._record_type(packet, xx, f"icmpv6-malformed-{int(packet['ICMPv6'].type)}")
                continue

            #print(packet)
            #print(dir(packet))

            # Unmerged fragments
            if int(packet['6lowpan'].pattern, base=16) in (0x1c, 0x18):
                # Do not do anything if this is a packet that has been reassembled
                if not hasattr(packet['6lowpan'], "reassembled_length"):

                    # Don't record this packet if it is going to be reassembled
                    if not hasattr(packet['6lowpan'], "reassembled_in"):
                        self._print_packet_attributes(packet, '6lowpan')
                        print(dir(packet))

                        self._record_type(packet, xx, "6lowpan-fragment")
                    continue

            # Virtually all packets should be here
            if 'coap' in packet:
                # coap other
                if packet['coap'].type.int_value == 2:
                    kind = self.packet_kinds.get(int(getattr(packet['coap'], "response_to", -1)), "coap-ack")
                    self._record_type(packet, xx, kind)
                    continue
                elif packet['coap'].type.int_value == 3:
                    self._record_type(packet, xx, "coap-reset")
                    continue

                if 'oscore' in packet:
                    #print(packet)
                    #print(dir(packet))

                    # mqtt-over-coap
                    if self._layer_matches_url(packet['oscore'], 'mqtt'):
                        self._record_type(packet, xx, "capability-pub-sub")
                        continue

                    if self._layer_matches_url(packet['oscore'], 'stereotype'):
                        self._record_type(packet, xx, "stereotype")
                        continue

                    if self._layer_matches_url(packet['oscore'], 'key'):
                        self._record_type(packet, xx, "certificate")
                        continue

                    if getattr(packet['oscore'], "_ws_expert_message", "") == 'Authentication tag check failed':
                        self._record_type(packet, xx, "oscore")
                        continue

                    self._print_packet_attributes(packet, 'coap', 'oscore')
                    raise RuntimeError(f"Unprocessed OSCORE packet")

                #print(packet['coap'])
                #print(packet['coap'].field_names)

                # We only use block responses for routing
                if hasattr(packet['coap'], "opt_block_number"):
                    self._record_type(packet, xx, "app-routing")
                    continue

                # mqtt-over-coap
                if self._layer_matches_url(packet['coap'], 'mqtt'):
                    self._record_type(packet, xx, "capability-pub-sub")
                    continue

                # trust dissemination
                if self._layer_matches_url(packet['coap'], 'trust'):
                    self._record_type(packet, xx, "trust-dissem")
                    continue
                    
                self._print_packet_attributes(packet, 'coap')
                raise RuntimeError(f"Unprocessed COAP packet")

            # Packet is in some way malformed
            if '_WS.MALFORMED' in packet:
                self._record_type(packet, xx, "malformed")
                continue

            self._print_packet_attributes(packet)
            raise RuntimeError(f"Unprocessed general packet")


def write_oscore_context_pref(log_dir):
    # Need to write a file that allows wireshark to decrypt OSCORE messages
    # File is comma separated with # as a comment, e.g.,
    """
    # This file is automatically generated, DO NOT MODIFY.
    "1","1","1","1","","AES-CCM-16-64-128 (CCM*)"
    "1","1","1","1","","AES-CCM-16-64-128 (CCM*)"
    """
    # Parameters are:
    # Sender ID, Recipient ID, Master Secret, Master Salt, ID Context, Algorithm
    # See: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-oscore.c#L828

    aiocoap_to_tshark_algorithm = {
        "AES-CCM-16-64-128": "AES-CCM-16-64-128 (CCM*)"
    }

    keystore = Keystore(f"{log_dir}/keystore")

    with open(os.path.abspath(f'{log_dir}/keystore/oscore.contexts.uat'), "w") as tshark_oscore_conf:

        salt = "642b2b8e9d0c4263924ceafcf7038b26"
        oscore_id_context = ""
        algorithm = "AES-CCM-16-64-128"

        # TODO: avoid hardcoding these setting by looking at the config
        """for context in os.listdir(f"{log_dir}/keystore/oscore-contexts"):
            with open(f"{log_dir}/keystore/oscore-contexts/{context}/secret.json") as secret:
                ctxdet = json.load(secret)

            salt = ctxdet["salt_hex"]
            algorithm = ctxdet["algorithm"]

            line = [
                ctxdet["sender-id_hex"],
                ctxdet["recipient-id_hex"],
                ctxdet["secret_hex"],
                ctxdet["salt_hex"],
                "",
                aiocoap_to_tshark_algorithm[ctxdet["algorithm"]]
            ]

            print(','.join(f'"{v}"' for v in line), file=tshark_oscore_conf)"""

        for sender, recipient in itertools.permutations(hostname_to_ips.values(), 2):
            if sender == recipient:
                continue

            line = [
                keystore.oscore_ident(sender).hex(),
                keystore.oscore_ident(recipient).hex(),
                keystore.shared_secret(sender, recipient).hex(),
                salt,
                oscore_id_context,
                aiocoap_to_tshark_algorithm[algorithm]
            ]

            print(','.join(f'"{v}"' for v in line), file=tshark_oscore_conf)

def main(log_dir):
    print(f"Looking for results in {log_dir}")

    write_oscore_context_pref(log_dir)

    override_prefs={
        'oscore.contexts': os.path.abspath(f'{log_dir}/keystore/oscore.contexts.uat')
    }

    gs = glob.glob(f"{log_dir}/*.new.pcap")
    #gs = glob.glob(f"{log_dir}/*.packet.log")

    results = {}

    for g in gs:
        print(f"Processing {g}...")
        bg = os.path.basename(g)

        kind, hostname, cr, log = bg.split(".", 3)

        if kind not in ("wsn", "edge"):
            print("Can only have pcap results from a wsn or edge node")
            continue

        a = PcapAnalyser(hostname)

        # Need pass "-2" in order for packets to be processed twice,
        # this means that fragments will be reassembled
        with pyshark.FileCapture(g, override_prefs=override_prefs, custom_parameters=["-2"], debug=True) as f:
            a.analyse(f)

        print(a.hostname, a.addrs, a.eui64)
        print(f"Tx Addrs: {a.tx_addrs}")
        print(f"Rx Addrs: {a.rx_addrs}")
        print()

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Challenge Response')
    parser.add_argument('--log-dir', type=str, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
