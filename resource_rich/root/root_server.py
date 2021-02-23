#!/usr/bin/env python3

import logging
import asyncio
import signal
import ipaddress

from .coap_key_server import COAPKeyServer
from .mqtt_coap_bridge import MQTTCOAPBridge
from .stereotype_server import StereotypeServer

from .keystore import Keystore

from common.configuration import root_node, hostname_to_ips

import aiocoap
import aiocoap.resource as resource
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
from aiocoap.credentials import CredentialsMap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("root-server")
logger.setLevel(logging.DEBUG)

# Get logging from aiocoap
logging.getLogger("coap").setLevel(logging.DEBUG)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def shutdown(signal, loop, bridge):
    """Cleanup tasks tied to the service's shutdown."""
    logger.info(f"Received exit signal {signal.name}...")

    await bridge.stop()

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        if task.done():
            continue
        task.cancel()

    logger.info(f"Cancelling {len(tasks)} outstanding tasks...")
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info(f"Finished cancelling tasks!")

    loop.stop()

def keystore_aiocoap_oscore_credentials(keystore: Keystore) -> CredentialsMap:
    root_address = ipaddress.ip_address(hostname_to_ips[root_node])

    addresses = [addr for addr in keystore.list_addresses() if addr != root_address]

    server_credentials_dict = {
        f":{keystore.oscore_ident(addr).hex()}": {
            "oscore": {
                "contextfile": f"{keystore.key_dir}/oscore-contexts/{keystore.oscore_ident(addr).hex()}/"
            }
        }

        for addr in addresses
    }

    # TODO: Fix this so it works

    # In order for messages sent from this application to others to be protected
    # we need to add this additional credential link in
    client_credentials_dict = {
        f"coap://{addr}/*": f":{keystore.oscore_ident(addr).hex()}"

        for addr in addresses
    }


    server_credentials = CredentialsMap()
    server_credentials.load_from_dict({**server_credentials_dict, **client_credentials_dict})

    #logger.debug("Credentials:")
    #for k, item in server_credentials.items():
    #    logger.debug(f"{k}:")
    #    logger.debug(f"\tSender ID    : {item.sender_id.hex()}")
    #    logger.debug(f"\tSender Key   : {item.sender_key.hex()}")
    #    logger.debug(f"\tRecipient ID : {item.recipient_id.hex()}")
    #    logger.debug(f"\tRecipient Key: {item.recipient_key.hex()}")
    #    logger.debug(f"\tCommon IV    : {item.common_iv.hex()}")

    return server_credentials

async def start(oscore_site: OscoreSiteWrapper, bridge: MQTTCOAPBridge):
    bridge.context = await aiocoap.Context.create_server_context(oscore_site)
    await bridge.start()

def main(mqtt_database,
         mqtt_flush,
         key_directory):
    logger.info("Starting root server")

    loop = asyncio.get_event_loop()

    keystore = Keystore(key_directory)
    server_credentials = keystore_aiocoap_oscore_credentials(keystore)

    coap_site = resource.Site()
    coap_site.add_resource(['.well-known', 'core'],
        resource.WKCResource(coap_site.get_resources_as_linkheader, impl_info=None))

    key_server = COAPKeyServer(keystore)
    coap_site.add_resource(['key'], OscoreSiteWrapper(key_server, server_credentials))

    bridge = MQTTCOAPBridge(mqtt_database)
    coap_site.add_resource(['mqtt'], OscoreSiteWrapper(bridge.coap_connector, server_credentials))

    stereotype = StereotypeServer()
    coap_site.add_resource(['stereotype'], OscoreSiteWrapper(stereotype, server_credentials))

    oscore_site = OscoreSiteWrapper(coap_site, server_credentials)

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, bridge)))

    try:
        loop.create_task(start(oscore_site, bridge))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the root coap server.")


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Root Server')
    # MQTT-over-coap options
    parser.add_argument('-d', '--mqtt-database', type=str, default="mqtt_coap_bridge.pickle", help='The location of serialised database')
    parser.add_argument('-f', '--mqtt-flush', action="store_true", default=False, help='Clear previous mqtt subscription database')

    # Key server options
    parser.add_argument('-k', '--key-directory', type=str, required=True, help='The location of serialised database')

    args = parser.parse_args()

    main(mqtt_database=args.mqtt_database,
         mqtt_flush=args.mqtt_flush,
         key_directory=args.key_directory)
