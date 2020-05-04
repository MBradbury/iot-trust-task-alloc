#!/usr/bin/env python

import logging
import asyncio
import signal

import asyncio_mqtt

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
import aiocoap.resource

# Need to patch _cb_and_generator to get msg contents instead of just payload
# See: https://github.com/sbtinstruments/asyncio-mqtt/issues/2
Client = asyncio_mqtt.Client
def _cb_and_generator(self, *, log_context, queue_maxsize=0):
        # Queue to hold the incoming messages
        messages = asyncio.Queue(maxsize=queue_maxsize)
        # Callback for the underlying API
        def _put_in_queue(client, userdata, msg):
            try:
                messages.put_nowait(msg)
            except asyncio.QueueFull:
                asyncio_mqtt.MQTT_LOGGER.warning(f'[{log_context}] Message queue is full. Discarding message.')
        # The generator that we give to the caller
        async def _message_generator():
            # Forward all messages from the queue
            while True:
                yield await messages.get()
        return _put_in_queue, _message_generator()
Client._cb_and_generator = _cb_and_generator


def mqtt_message_to_str(message):
    """__str__ impelementation for https://github.com/eclipse/paho.mqtt.python/blob/master/src/paho/mqtt/client.py#L355"""
    return ", ".join(f"{slot}={getattr(message, slot, None)}" for slot in type(message).__slots__)


class Clients:
    def __init__(self):
        pass


class NonMQTTOperation(error.RenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Not an MQTT operation"

class COAPConnector(aiocoap.resource.Resource):
    def __init__(self, bridge):
        super().__init__()
        self.bridge = bridge

    async def start(self):
        self.context = await aiocoap.Context.create_server_context(self)

    async def stop(self):
        pass

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
    def __init__(self):
        self.coap_connector = COAPConnector(self)
        self.mqtt_connector = MQTTConnector(self)

    async def start(self):
        await self.coap_connector.start()
        await self.mqtt_connector.start()

    async def stop(self):
        await self.coap_connector.stop()
        await self.mqtt_connector.stop()

    async def coap_to_mqtt_subscribe(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)

        try:
            result = await self.mqtt_connector.client.subscribe(topic)

            print(result)

            logging.info(f"Subscribed to {topic} from {request.remote}...")

            result = aiocoap.Message(payload=b"", code=codes.CREATED)
        except Exception as ex:
            result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)

        # TODO: update local table of clients who are subscribed

        return result

    async def coap_to_mqtt_unsubscribe(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)

        try:
            result = await self.mqtt_connector.client.unsubscribe(topic)

            print(result)

            logging.info(f"Unsubscribed to {topic} from {request.remote}...")

            result = aiocoap.Message(payload=b"", code=codes.DELETED)
        except Exception as ex:
            result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)

        # TODO: update local table of clients who are subscribed

        return result

    async def coap_to_mqtt_publish(self, request):
        topic = self._coap_request_extract_mqtt_topic(request)

        try:
            await self.mqtt_connector.client.publish(topic, request.payload, qos=1)

            logging.info(f"Published {request.payload} to {topic} from {request.remote}...")

            result = aiocoap.Message(payload=b"", code=codes.CONTENT)
        except Exception as ex:
            result = aiocoap.Message(payload=f"{ex}".encode("utf-8"), code=codes.BAD_REQUEST)

        return result

    async def mqtt_to_coap_publish(self, message):
        logging.info(f"MQTT pushed {mqtt_message_to_str(message)}")

        # TODO: Push via CoAP to all subscribed clients


    def _coap_request_extract_mqtt_topic(self, request):
        if request.opt.uri_path[0] != "mqtt":
            raise NonMQTTOperation()

        return "/".join(request.opt.uri_path[1:])


logging.basicConfig(level=logging.INFO)
logging.getLogger("mqtt-coap-bridge").setLevel(logging.DEBUG)

async def shutdown(signal, loop, bridge):
    """Cleanup tasks tied to the service's shutdown."""
    logging.info(f"Received exit signal {signal.name}...")

    await bridge.stop()

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    logging.info(f"Cancelling {len(tasks)} outstanding tasks")

    await asyncio.gather(*tasks)

    logging.info(f"Flushing metrics")
    loop.stop()

def main():
    loop = asyncio.get_event_loop()

    bridge = MQTTCOAPBridge()

    # May want to catch other signals too
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for sig in signals:
        loop.add_signal_handler(sig, lambda sig=sig: asyncio.create_task(shutdown(sig, loop, bridge)))

    try:
        loop.create_task(bridge.start())
        loop.run_forever()
    finally:
        loop.close()
        logging.info("Successfully shutdown the mqtt-coap bridge.")

if __name__ == "__main__":
    main()
