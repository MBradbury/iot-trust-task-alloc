#!/usr/bin/env python3
from __future__ import annotations

import glob
import os
from pprint import pprint
from collections import defaultdict
import ipaddress
import textwrap
import pathlib
import itertools

from resource_rich.root.keystore import Keystore

from common.configuration import hostname_to_ips

from tools.keygen.util import ip_to_eui64

import pyshark
from pyshark.packet.packet import Packet

class PcapAnalyser:
    def __init__(self, hostname: str, quiet: bool=False):
        self.hostname = hostname
        self.addr = hostname_to_ips[hostname]
        self.addrs = {
            # With prefix
            self.addr,

            # Link local
            ipaddress.IPv6Address("fe80" + str(self.addr)[4:]),

            # No prefix
            ipaddress.IPv6Address(str(self.addr)[4:]),
        }

        eui64_bytes = ip_to_eui64(self.addr)
        self.eui64 = ':'.join(textwrap.wrap(eui64_bytes.hex(), 2))

        self.tx = defaultdict(list)
        self.rx = defaultdict(list)

        self.tx_addrs = set()
        self.rx_addrs = set()

        self.min_snift_time = None
        self.max_snift_time = None

        self.packet_kinds = {}

        self.quiet = quiet

    def get_tx_rx_list(self, packet: Packet) -> Dict[str, List[Packet]]:
        try:
            addr = ipaddress.IPv6Address(packet['6lowpan'].src)
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

    def _layer_matches_url(self, layer: str, uri: str) -> bool:
        return getattr(layer, "opt_uri_path", "") in (uri, f'/{uri}') or \
               getattr(layer, "opt_uri_path_recon", "") in (uri, f'/{uri}')

    def _print_packet_attributes(self, packet: Packet, *layers):
        if not self.quiet:
            print(packet)
            for layer in layers:
                print(layer, {n: getattr(packet[layer], n) for n in packet[layer].field_names})

    def _record_type(self, packet: Packet, xx: Dict[str, List[Packet]], kind: str):
        xx[kind].append(packet)

        self.packet_kinds[int(packet.number)] = kind
        
    def analyse(self, packets: pyshark.FileCapture):
        seen_cap_pub_sub_reqs = set()

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
                        # Record the token from the request, so we can match the response
                        token = getattr(packet['coap'], "token", None)
                        if token:
                            seen_cap_pub_sub_reqs.add(packet['coap'].token)

                        self._record_type(packet, xx, "capability-pub-sub")
                        continue

                    if self._layer_matches_url(packet['oscore'], 'stereotype'):
                        self._record_type(packet, xx, "stereotype")
                        continue

                    if self._layer_matches_url(packet['oscore'], 'key'):
                        self._record_type(packet, xx, "certificate")
                        continue

                    # Unable to decrypt and authenticate properly
                    if getattr(packet['oscore'], "_ws_expert_message", "") == 'Authentication tag check failed':

                        # For some reason wireshark does not handle the reassembled block1 messages
                        # used by the routing application, so if this is one of those, lets ignore it
                        # We count the individual block1 messages later
                        if getattr(packet['coap'], "blocks", "") != "":
                            continue

                        self._record_type(packet, xx, "oscore-nd")
                        self._print_packet_attributes(packet, 'coap', 'oscore')
                        continue

                    # This is a response from the mqtt-coap-bridge
                    if getattr(packet['coap'], "code", "") == "68": # 2.04 changed
                        token = getattr(packet['coap'], "token", None)
                        if token is not None and token in seen_cap_pub_sub_reqs:
                            self._record_type(packet, xx, "capability-pub-sub")
                            continue

                    self._print_packet_attributes(packet, 'coap', 'oscore')
                    raise RuntimeError(f"Unprocessed OSCORE packet")

                #print(packet['coap'])
                #print(packet['coap'].field_names)

                if self._layer_matches_url(packet['coap'], 'routing'):
                    self._record_type(packet, xx, "app-routing")
                    continue

                if self._layer_matches_url(packet['coap'], 'envmon'):
                    self._record_type(packet, xx, "app-envmon")
                    continue

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

                if getattr(packet['coap'], "_ws_expert_message", "") == "end-of-options marker found, but option delta isn't 15":
                    self._record_type(packet, xx, "coap-malformed")
                    continue

                if "Unknown Option Number" in getattr(packet['coap'], "_ws_expert_message", ""):
                    self._record_type(packet, xx, "coap-malformed")
                    continue
                if "Invalid Option Number" in getattr(packet['coap'], "_ws_expert_message", ""):
                    self._record_type(packet, xx, "coap-malformed")
                    continue
                if "Invalid Option Range" in getattr(packet['coap'], "_ws_expert_message", ""):
                    self._record_type(packet, xx, "coap-malformed")
                    continue
                if "Trailing stray characters" in getattr(packet['coap'], "_ws_expert_message", ""):
                    self._record_type(packet, xx, "coap-malformed")
                    continue

                code = getattr(packet['coap'], "code", "")
                if code: # 5.03 service unavailable
                    self._record_type(packet, xx, f"coap-{code}")
                    continue

                self._print_packet_attributes(packet, 'coap')
                raise RuntimeError(f"Unprocessed COAP packet")

            # Packet is in some way malformed
            if '_WS.MALFORMED' in packet:
                self._record_type(packet, xx, "malformed")
                continue

            self._print_packet_attributes(packet)
            raise RuntimeError(f"Unprocessed general packet")

def main(log_dir: pathlib.Path, quiet: bool=False) -> Dict[str, PcapAnalyser]:
    print(f"Looking for results in {log_dir}")

    override_prefs={
        'oscore.contexts': str((log_dir / "keystore" / "oscore.contexts.uat").resolve())
    }

    gs = log_dir.glob("*.pcap")

    results = {}

    for g in gs:
        print(f"Processing {g}...")

        kind, hostname, *_ = g.name.split(".")

        kind_options = {"wsn", "edge", "adversary"}
        if kind not in kind_options:
            print(f"Can only have pcap results from one of {kind_options}")
            continue

        a = PcapAnalyser(hostname, quiet)

        # Need pass "-2" in order for packets to be processed twice,
        # this means that fragments will be reassembled
        with pyshark.FileCapture(str(g), override_prefs=override_prefs, custom_parameters=["-2"], debug=True, keep_packets=False) as cap:
            a.analyse(cap)

        print(a.hostname, a.addrs, a.eui64)
        print(f"Tx Addrs: {a.tx_addrs}")
        print(f"Rx Addrs: {a.rx_addrs}")
        print()

        results[hostname] = a

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse Challenge Response')
    parser.add_argument('--log-dir', type=pathlib.Path, default="results", help='The directory which contains the log output')

    args = parser.parse_args()

    main(args.log_dir)
