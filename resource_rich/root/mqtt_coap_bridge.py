#!/usr/bin/env python3
from __future__ import annotations

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
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

import aiocoap
import aiocoap.error as error
from aiocoap.numbers import media_types, media_types_rev
import aiocoap.numbers.codes as codes
import aiocoap.resource as resource
from aiocoap.transports.oscore import OSCOREAddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mqtt-coap-bridge")
logger.setLevel(logging.DEBUG)

class MQTTToCoAPError(error.ConstructionRenderableError):
    def __init__(self, mqtt_error_code):
        super().__init__(mqtt.error_string(mqtt_error_code))

class MissingMQTTTopic(error.BadRequest):
    message = "Error: MQTT topic not provided"

def mqtt_message_to_str(message):
    """__str__ impelementation for https://github.com/eclipse/paho.mqtt.python/blob/master/src/paho/mqtt/client.py#L355"""
    return ", ".join(f"{slot}={getattr(message, slot, None)}" for slot in type(message).__slots__)


class SubscriptionManager:
    def __init__(self, database: str):
        self._subscriptions = defaultdict(set)
        self._lock = asyncio.Lock()
        self._database = database

    async def should_subscribe(self, topic: str, source: str) -> bool:
        async with self._lock:
            return len(self._subscriptions[topic]) == 0

    async def should_unsubscribe(self, topic: str, source: str) -> bool:
        async with self._lock:
            try:
                return len(self._subscriptions[topic]) == 1 and source in self._subscriptions[topic]
            except KeyError:
                # No subscriptions, so do not need to subscribe
                return False

    async def subscribe(self, topic: str, source: str):
        async with self._lock:
            self._subscriptions[topic].add(source)

            # Persist to disk
            with open(self._database, "wb") as db:
                pickle.dump(self._subscriptions, db)

    async def unsubscribe(self, topic: str, source: str):
        async with self._lock:
            try:
                self._subscriptions[topic].remove(source)

                # Persist to disk
                with open(self._database, "wb") as db:
                    pickle.dump(self._subscriptions, db)
            except KeyError as ex:
                logger.error(f"Failed to remove subscription to {topic} from {source} with {ex}")

    async def subscribers(self, topic: str) -> Set[str]:
        async with self._lock:
            subscriptions = copy.deepcopy(self._subscriptions)

        subs = set()

        for subscription in subscriptions:
            if mqtt.topic_matches_sub(subscription, topic):
                subs.update(subscriptions[subscription])

        return subs

    def deserialise(self) -> List[str]:
        try:
            # Load _subscriptions from database
            with open(self._database, "rb") as db:
                self._subscriptions = pickle.load(db)

            logger.info(f"Loaded subscriptions from {self._database}")
        except FileNotFoundError as ex:
            logger.warning(f"Failed to load subscriptions from {self._database} because {ex}")

        return list(self._subscriptions.keys())


class COAPConnector(resource.Resource):
    def __init__(self, bridge):
        super().__init__()
        self.bridge = bridge

    async def render_get(self, request: aiocoap.Message) -> aiocoap.Message:
        """An MQTT Subscribe request"""
        try:
            return await self.bridge.coap_to_mqtt_subscribe(request)

        except asyncio_mqtt.error.MqttCodeError as ex:
            raise MQTTToCoAPError(ex.rc)
        except ValueError as ex:
            raise error.BadRequest(str(ex))

    async def render_delete(self, request: aiocoap.Message) -> aiocoap.Message:
        """An MQTT unsubscribe request"""
        try:
            return await self.bridge.coap_to_mqtt_unsubscribe(request)

        except asyncio_mqtt.error.MqttCodeError as ex:
            raise MQTTToCoAPError(ex.rc)
        except ValueError as ex:
            raise error.BadRequest(str(ex))

    async def render_put(self, request: aiocoap.Message) -> aiocoap.Message:
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
        self.client = asyncio_mqtt.Client('::1', protocol=mqtt.MQTTv5)
        self._on_publish_task = None

    async def start(self):
        await self.client.connect()

        self._on_publish_task = asyncio.create_task(self.on_publish())

    async def stop(self):
        self._on_publish_task.cancel()
        try:
            await self._on_publish_task
        except asyncio.CancelledError:
            pass

        await self.client.disconnect()

    async def on_publish(self):
        async with self.client.unfiltered_messages() as messages:
            async for message in messages:
                await self.bridge.mqtt_to_coap_publish(message)


class MQTTCOAPBridge:
    def __init__(self, database: str):
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

    async def coap_to_mqtt_subscribe(self, request: aiocoap.Message) -> aiocoap.Message:
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        if await self.manager.should_subscribe(topic, host):
            await self.mqtt_connector.client.subscribe(topic)

        # Subscribe succeeded, or
        # Already subscribed, so just say things were fine.
        result = aiocoap.Message(payload=b"", code=codes.CREATED)

        # Update local table of clients who are subscribed
        logger.info(f"Subscribed {host} to {topic}")
        await self.manager.subscribe(topic, host)

        return result

    async def coap_to_mqtt_unsubscribe(self, request: aiocoap.Message) -> aiocoap.Message:
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        if await self.manager.should_unsubscribe(topic, host):
            await self.mqtt_connector.client.unsubscribe(topic)

        # Unsubscribe succeeded, or
        # Not currently subscribed, so just say things were fine.
        result = aiocoap.Message(payload=b"", code=codes.DELETED)

        # Update local table of clients who are subscribed
        logger.info(f"Unsubscribed {host} from {topic}")
        await self.manager.unsubscribe(topic, host)

        return result

    async def coap_to_mqtt_publish(self, request: aiocoap.Message) -> aiocoap.Message:
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        # Pass the request content_format as a property
        properties = Properties(PacketTypes.PUBLISH)
        properties.ContentType = media_types[request.opt.content_format]

        await self.mqtt_connector.client.publish(topic, request.payload, properties=properties)

        logger.info(f"Published CoAP message to MQTT of length {len(request.payload)} for {topic} from {host} with {properties}")

        return aiocoap.Message(payload=b"", code=codes.CONTENT)

    async def mqtt_to_coap_publish(self, message):
        subscribers = await self.manager.subscribers(message.topic)

        logger.info(f"MQTT pushed {mqtt_message_to_str(message)} forwarding to {subscribers} via CoAP")

        # Set content type when the publish is received from the MQTT server
        content_format = None
        if message.properties is not None:
            content_format = media_types_rev[message.properties.ContentType]

        # Push via CoAP to all subscribed clients
        await asyncio.gather(*[
            self.forward_mqtt(message.payload, message.topic, subscriber, content_format)
            for subscriber in subscribers
        ])

    async def forward_mqtt(self, payload: bytes, topic: str, target: str, content_format: Optional[int]):
        """Forward an MQTT message to a coap target"""
        message = aiocoap.Message(code=codes.POST, payload=payload,
                                  uri=f"coap://[{target}]/mqtt?t={topic}",
                                  content_format=content_format)

        logger.info(f"Forwarding MQTT over CoAP {message} to {target} with topic {topic} and content format {content_format}")

        response = None

        try:
            response = await asyncio.wait_for(self.context.request(message).response, timeout=10)

            logger.info(f"Forwarding MQTT over CoAP to {target} response: {response}")
        except (asyncio.TimeoutError, error.RequestTimedOut) as ex:
            logger.warning(f"Forwarding MQTT over CoAP to {target} timed out {ex}")

        return response

    def _coap_request_extract_mqtt_topic(self, request: aiocoap.Message) -> str:
        for query in request.opt.uri_query:
            k,v = query.split("=", 1)

            if k == "t":
                return v

        raise MissingMQTTTopic()

    def _coap_request_extract_host(self, request: aiocoap.Message):
        if isinstance(request.remote, OSCOREAddress):
            return request.remote.underlying_address.sockaddr[0]
        else:
            return request.remote.sockaddr[0]


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

async def start(coap_site, bridge):
    bridge.context = await aiocoap.Context.create_server_context(coap_site)
    await bridge.start()

def main(database: str, flush: bool=False):
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
    
    bridge = MQTTCOAPBridge(database)
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
    parser.add_argument('-d', '--mqtt-database', type=str, default="mqtt_coap_bridge.pickle", help='The location of serialised database')
    parser.add_argument('-f', '--mqtt-flush', action="store_true", default=False, help='Clear previous mqtt subscription database')

    args = parser.parse_args()

    main(database=args.mqtt_database, flush=args.mqtt_flush)
