#!/usr/bin/env python3

import logging
import asyncio
import signal
from collections import defaultdict
import urllib.parse
import copy
import pickle
import os

import asyncio_mqtt
import asyncio_mqtt.error
import paho.mqtt.client as mqtt

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
import aiocoap.resource as resource

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mqtt-coap-bridge")
logger.setLevel(logging.DEBUG)

class MQTTToCoAPError(error.ConstructionRenderableError):
    def __init__(self, mqtt_error_code):
        super().__init__(mqtt.error_string(mqtt_error_code))

def mqtt_message_to_str(message):
    """__str__ impelementation for https://github.com/eclipse/paho.mqtt.python/blob/master/src/paho/mqtt/client.py#L355"""
    return ", ".join(f"{slot}={getattr(message, slot, None)}" for slot in type(message).__slots__)


class SubscriptionManager:
    def __init__(self, database):
        self._subscriptions = defaultdict(set)
        self._lock = asyncio.Lock()
        self._database = database

    async def should_subscribe(self, topic, source):
        async with self._lock:
            return len(self._subscriptions[topic]) == 0

    async def should_unsubscribe(self, topic, source):
        async with self._lock:
            try:
                return len(self._subscriptions[topic]) == 1 and source in self._subscriptions[topic]
            except KeyError:
                # No subscriptions, so do not need to subscribe
                return False

    async def subscribe(self, topic, source):
        async with self._lock:
            self._subscriptions[topic].add(source)

            # Persist to disk
            with open(self._database, "wb") as db:
                pickle.dump(self._subscriptions, db)

    async def unsubscribe(self, topic, source):
        async with self._lock:
            try:
                self._subscriptions[topic].remove(source)

                # Persist to disk
                with open(self._database, "wb") as db:
                    pickle.dump(self._subscriptions, db)
            except KeyError as ex:
                logger.error(f"Failed to remove subscription to {topic} from {source} with {ex}")

    async def subscribers(self, topic):
        async with self._lock:
            subscriptions = copy.deepcopy(self._subscriptions)

        subs = set()

        for subscription in subscriptions:
            if mqtt.topic_matches_sub(subscription, topic):
                subs.update(subscriptions[subscription])

        return subs

    def deserialise(self):
        try:
            # Load _subscriptions from database
            with open(self._database, "rb") as db:
                self._subscriptions = pickle.load(db)

            logger.info(f"Loaded subscriptions from {self._database}")
        except FileNotFoundError as ex:
            logger.warning(f"Failed to load subscriptions from {self._database} because {ex}")

        return list(self._subscriptions.keys())

class MissingMQTTTopic(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: MQTT topic not provided"

class COAPConnector(resource.Resource):
    def __init__(self, bridge):
        super().__init__()
        self.bridge = bridge

    """async def start(self):
        pass
        #self.context = await aiocoap.Context.create_server_context(self.bridge.coap_site)

        # See: https://github.com/chrysn/aiocoap/blob/master/aiocoap/transports/tinydtls.py#L29
        "" "self.context.client_credentials.load_from_dict({
            'coaps://localhost/*': {
                'dtls': {
                    'psk': b'secretPSK',
                    'client-identity': b'client_Identity',
                }
            }
        })"""

    #async def stop(self):
    #    pass
    #    #await self.context.shutdown()

    async def render_get(self, request):
        """An MQTT Subscribe request"""
        try:
            return await self.bridge.coap_to_mqtt_subscribe(request)

        except asyncio_mqtt.error.MqttCodeError as ex:
            raise MQTTToCoAPError(ex.rc)
        except ValueError as ex:
            raise error.BadRequest(str(ex))

    async def render_delete(self, request):
        """An MQTT unsubscribe request"""
        try:
            return await self.bridge.coap_to_mqtt_unsubscribe(request)

        except asyncio_mqtt.error.MqttCodeError as ex:
            raise MQTTToCoAPError(ex.rc)
        except ValueError as ex:
            raise error.BadRequest(str(ex))

    async def render_put(self, request):
        """An MQTT publish request"""
        try:
            return await self.bridge.coap_to_mqtt_publish(request)

        except asyncio_mqtt.error.MqttCodeError as ex:
            raise MQTTToCoAPError(ex.rc)
        except ValueError as ex:
            raise error.BadRequest(str(ex))


class MQTTConnector:
    def __init__(self, bridge):
        self.bridge = bridge
        self.client = asyncio_mqtt.Client('::1')

    async def start(self):
        await self.client.connect()
        asyncio.create_task(self.on_publish())

    async def stop(self):
        await self.client.disconnect()

    async def on_publish(self):
        async with self.client.unfiltered_messages() as messages:
            async for message in messages:
                await self.bridge.mqtt_to_coap_publish(message)


class MQTTCOAPBridge:
    def __init__(self, database, coap_target_port):
        self.coap_target_port = coap_target_port
        self.coap_connector = COAPConnector(self)
        self.mqtt_connector = MQTTConnector(self)
        self.manager = SubscriptionManager(database)
        self.context = None

    async def start(self):
        await self.mqtt_connector.start()

        # Try and load saved subscriptions
        topics = self.manager.deserialise()
        for topic in topics:
            try:
                await self.mqtt_connector.client.subscribe(topic)
                logger.info(f"Subscribe to saved topic {topic}")
            except MqttCodeError as ex:
                logger.error(f"Failed to subscribe to {topic} due to {mqtt.error_string(ex.rc)}")

    async def stop(self):
        await self.mqtt_connector.stop()

    async def coap_to_mqtt_subscribe(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        if await self.manager.should_subscribe(topic, host):
            await self.mqtt_connector.client.subscribe(topic)

        # Subscribe succeeded, or
        # Already subscribed, so just say things were fine.
        result = aiocoap.Message(payload=b"", code=codes.CREATED)

        # Update local table of clients who are subscribed
        if result.code == codes.CREATED:
            logger.info(f"Subscribed {host} to {topic}")
            await self.manager.subscribe(topic, host)
        else:
            logger.error(f"Failed to subscribe {host} to {topic} ({result})")

        return result

    async def coap_to_mqtt_unsubscribe(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        if await self.manager.should_unsubscribe(topic, host):
            await self.mqtt_connector.client.unsubscribe(topic)

        # Ubsubscribe succeeded, or
        # Not currently subscribed, so just say things were fine.
        result = aiocoap.Message(payload=b"", code=codes.DELETED)

        # Update local table of clients who are subscribed
        if result.code == codes.DELETED:
            logger.info(f"Unsubscribed {host} from {topic}")
            await self.manager.unsubscribe(topic, host)
        else:
            logger.error(f"Failed to subscribe {host} to {topic} ({result})")

        return result

    async def coap_to_mqtt_publish(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        await self.mqtt_connector.client.publish(topic, request.payload, qos=1)

        logger.info(f"Published {request.payload} to {topic} from {host}")

        result = aiocoap.Message(payload=b"", code=codes.CONTENT)

        return result

    async def mqtt_to_coap_publish(self, message):
        subscribers = await self.manager.subscribers(message.topic)

        logger.info(f"MQTT pushed {mqtt_message_to_str(message)} forwarding to {subscribers}")

        # Push via CoAP to all subscribed clients
        # TODO: need to handle error.RequestTimedOut from forward_mqtt
        await asyncio.gather(*[
            self.forward_mqtt(message.payload, message.topic, subscriber)
            for subscriber in subscribers
        ])

    async def forward_mqtt(self, payload, topic, target):
        """Forward an MQTT message to a coap target"""
        message = aiocoap.Message(code=codes.POST, payload=payload,
                                  uri=f"coap://[{target}]:{self.coap_target_port}/mqtt?t={topic}")

        logger.info(f"Forwarding MQTT over CoAP {message} to {target}")

        try:
            response = await self.context.request(message).response

            logger.info(f"Forwarding MQTT over CoAP to {target} response: {response}")
        except error.RequestTimedOut as ex:
            logger.warning(f"Forwarding MQTT over CoAP to {target} timed out {ex}")

            response = None

        return response

    def _coap_request_extract_mqtt_topic(self, request):
        for query in request.opt.uri_query:
            k,v = query.split("=", 1)

            if k == "t":
                return v

        raise MissingMQTTTopic()

    def _coap_request_extract_host(self, request):
        return request.remote.sockaddr[0]



async def shutdown(signal, loop, bridge):
    """Cleanup tasks tied to the service's shutdown."""
    logger.info(f"Received exit signal {signal.name}...")

    await bridge.stop()

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    logger.info(f"Cancelling {len(tasks)} outstanding tasks...")
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info(f"Finished cancelling tasks!")

    loop.stop()

async def start(coap_site, bridge):
    bridge.context = await aiocoap.Context.create_server_context(coap_site)
    await bridge.start()

def main(database, coap_target_port, flush=False):
    logger.info("Starting mqtt-coap bridge")

    loop = asyncio.get_event_loop()

    if flush:
        try:
            os.remove(database)
        except FileNotFoundError:
            pass

    coap_site = resource.Site()
    coap_site.add_resource(['.well-known', 'core'],
        resource.WKCResource(coap_site.get_resources_as_linkheader, impl_info=None))
    
    bridge = MQTTCOAPBridge(database, coap_target_port)
    coap_site.add_resource(['mqtt'], bridge.coap_connector)

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, bridge)))

    try:
        loop.create_task(start(coap_site, bridge))
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the mqtt-coap bridge.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='MQTT-CoAP Bridge')
    parser.add_argument('-p', '--coap-target-port', type=int, default=5683, help='The target port for CoAP messages to be POSTed to')
    parser.add_argument('-d', '--mqtt-database', type=str, default="mqtt_coap_bridge.pickle", help='The location of serialised database')
    parser.add_argument('-f', '--mqtt-flush', action="store_true", default=False, help='Clear previous mqtt subscription database')

    args = parser.parse_args()

    main(database=args.mqtt_database, coap_target_port=args.coap_target_port, flush=args.mqtt_flush)
