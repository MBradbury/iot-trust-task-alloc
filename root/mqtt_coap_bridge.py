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
import paho.mqtt.client as mqtt

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
import aiocoap.resource

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mqtt-coap-bridge")
logger.setLevel(logging.DEBUG)

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

class NonMQTTOperation(error.RenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Not an MQTT operation"

class COAPConnector(aiocoap.resource.Resource):
    def __init__(self, bridge, coap_target_port):
        super().__init__()
        self.bridge = bridge
        self.coap_target_port = coap_target_port

    async def start(self):
        self.context = await aiocoap.Context.create_server_context(self)

    async def stop(self):
        await self.context.shutdown()

    async def render_get(self, request):
        """An MQTT Subscribe request"""
        if request.opt.uri_path == ('.well-known', 'core'):
            return aiocoap.Message(payload=b"</>;ct=40", content_format=40)

        return await self.bridge.coap_to_mqtt_subscribe(request)

    async def render_delete(self, request):
        """An MQTT unsubscribe request"""
        return await self.bridge.coap_to_mqtt_unsubscribe(request)

    async def render_put(self, request):
        """An MQTT publish request"""
        return await self.bridge.coap_to_mqtt_publish(request)

    async def forward_mqtt(self, payload, topic, target):
        """Forward an MQTT message to a coap target"""
        message = aiocoap.Message(code=codes.POST, payload=payload, uri=f"coap://[{target}]:{self.coap_target_port}/mqtt/{topic}")

        logger.info(f"Forwarding MQTT over CoAP {message} to {target}")

        try:
            response = await self.context.request(message).response

            logger.info(f"Forwarding MQTT over CoAP to {target} response: {response}")
        except error.RequestTimedOut as ex:
            logger.warning(f"Forwarding MQTT over CoAP to {target} timed out {ex}")

            response = None

        return response


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
        self.coap_connector = COAPConnector(self, coap_target_port)
        self.mqtt_connector = MQTTConnector(self)
        self.manager = SubscriptionManager(database)

    async def start(self):
        await self.mqtt_connector.start()

        # Try and load saved subscriptions
        topics = self.manager.deserialise()
        for topic in topics:
            result = await self.mqtt_connector.client.subscribe(topic)
            if result[0] != mqtt.MQTT_ERR_SUCCESS:
                logger.error(f"Failed to subscribe to {topic} due to {mqtt.error_string(result[0])}")
            else:
                logger.info(f"Subscribe to saved topic {topic}")

        await self.coap_connector.start()

    async def stop(self):
        await self.coap_connector.stop()
        await self.mqtt_connector.stop()

    async def coap_to_mqtt_subscribe(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)
        host = self._coap_request_extract_host(request)

        if await self.manager.should_subscribe(topic, host):
            try:
                result = await self.mqtt_connector.client.subscribe(topic)

                if result[0] == mqtt.MQTT_ERR_SUCCESS:
                    result = aiocoap.Message(payload=b"", code=codes.CREATED)
                else:
                    result = aiocoap.Message(payload=mqtt.error_string(result[0]).encode("utf-8"), code=codes.INTERNAL_SERVER_ERROR)

            except Exception as ex:
                result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)
        else:
            # Already subscribed, so just say things were fine
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
            try:
                result = await self.mqtt_connector.client.unsubscribe(topic)

                if result[0] == mqtt.MQTT_ERR_SUCCESS:
                    result = aiocoap.Message(payload=b"", code=codes.DELETED)
                else:
                    result = aiocoap.Message(payload=mqtt.error_string(result[0]).encode("utf-8"), code=codes.INTERNAL_SERVER_ERROR)

            except Exception as ex:
                result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)
        else:
            # Not currently subscribed, so just say things were fine
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

        try:
            await self.mqtt_connector.client.publish(topic, request.payload, qos=1)

            logger.info(f"Published {request.payload} to {topic} from {host}")

            result = aiocoap.Message(payload=b"", code=codes.CONTENT)
        except Exception as ex:
            result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)

        return result

    async def mqtt_to_coap_publish(self, message):
        subscribers = await self.manager.subscribers(message.topic)

        logger.info(f"MQTT pushed {mqtt_message_to_str(message)} forwarding to {subscribers}")

        # Push via CoAP to all subscribed clients
        # TODO: need to handle error.RequestTimedOut from forward_mqtt
        await asyncio.gather(*[
            self.coap_connector.forward_mqtt(message.payload, message.topic, subscriber)
            for subscriber in subscribers
        ])

    def _coap_request_extract_mqtt_topic(self, request):
        if request.opt.uri_path[0] != "mqtt":
            raise NonMQTTOperation()

        return "/".join(request.opt.uri_path[1:])

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

def main(database, coap_target_port, flush=False):
    logger.info("Starting mqtt-coap bridge")

    loop = asyncio.get_event_loop()

    if flush:
        try:
            os.remove(database)
        except FileNotFoundError:
            pass

    bridge = MQTTCOAPBridge(database, coap_target_port)

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, bridge)))

    try:
        loop.create_task(bridge.start())
        loop.run_forever()
    finally:
        loop.close()
        logger.info("Successfully shutdown the mqtt-coap bridge.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='MQTT-CoAP Bridge')
    parser.add_argument('-p', '--coap-target-port', type=int, default=5683, help='The target port for CoAP messages to be POSTed to')
    parser.add_argument('-d', '--database', type=str, default="mqtt_coap_bridge.pickle", help='The location of serialised database')
    parser.add_argument('-f', '--flush', action="store_true", default=False, help='Clear previous database')

    args = parser.parse_args()

    main(database=args.database, coap_target_port=args.coap_target_port, flush=args.flush)
