#!/usr/bin/env python3
from __future__ import annotations

import logging
import random
import asyncio

from routing import RoutingClient as RoutingClientGood, NAME, _format_route
import client_common
from bad import PeriodicBad, FakeRestartClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"app-{NAME}-bad")
logger.setLevel(logging.DEBUG)

MISBEHAVE_CHOICES = ["bad-response", "no-response"]
BAD_RESPONSE_CHOICES = ["success", "no_route", "gave_up"]

# From: https://gist.github.com/botzill/fc2a1581873200739f6dc5c1daf85a7d
GBR_LAT_LONG_NOTH_EAST = (61.061, 2.0919117)
GBR_LAT_LONG_SOUTH_WEST = (49.674, -14.015517)

class RoutingClientBad(RoutingClientGood, FakeRestartClient):
    def __init__(self, approach: str, duration: float,
                 fake_app_restart_period: Optional[float], fake_srvr_restart_period: Optional[float]):
        super().__init__()

        self.approach = approach

        self.bad = PeriodicBad(duration, NAME, self._bad_changed)

        self.fake_app_restart_period = fake_app_restart_period
        self.fake_srvr_restart_period = fake_srvr_restart_period

    async def start(self):
        await super().start()
        self.bad.start()

    async def shutdown(self):
        self.bad.shutdown()
        await super().shutdown()

    def _bad_changed(self):
        # If we have just become good, then during our bad period the trust/reputation
        # values for us may have decreased. So lets try unannouncing and reanncouncing ourselves.
        # Some IoT devices may choose to remove the stored trust values for us because of this.
        if not self.bad.is_bad:
            if self.fake_srvr_restart_period is not None:
                self._do_fake_restart_server(self.fake_srvr_restart_period)

            elif self.fake_app_restart_period is not None:
                self._do_fake_restart_application(self.fake_app_restart_period)

    async def _send_result(self, dest, message_response):
        if self.bad.is_bad:
            await self._write_task_stats()

            if self.approach == "random":
                selected_approach = random.choice(MISBEHAVE_CHOICES)
            else:
                selected_approach = self.approach

            logger.debug(f"Currently bad, so behaving incorrectly with {selected_approach}")

            # Instead of sending a result, we pick one of two options
            # 1. Send a bad response
            # 2. Don't send any response

            if selected_approach == "bad-response":
                # Pick which bad response to send
                selected_bad_response = random.choice(BAD_RESPONSE_CHOICES)

                logger.debug(f"Selected bad response {selected_bad_response}")

                if selected_bad_response == "success":
                    # Need to generate some random points for the route

                    route_length = random.randint(10, 20)

                    route_coords = [
                        (random.uniform(GBR_LAT_LONG_SOUTH_WEST[0], GBR_LAT_LONG_NOTH_EAST[0]),
                         random.uniform(GBR_LAT_LONG_SOUTH_WEST[1], GBR_LAT_LONG_NOTH_EAST[1]))

                        for x in range(route_length)
                    ]

                    message_response = (0, _format_route(route_coords))

                elif selected_bad_response == "no_route":
                    message_response = (1, None)
                elif selected_bad_response == "gave_up":
                    message_response = (2, None)
                else:
                    message_response = (3, None)

                # Send the bad message response
                await super()._send_result(dest, message_response)

            elif selected_approach == "no-response":
                # Nothing to do
                pass

            else:
                logger.error(f"Unknown misbehaviour {selected_approach}")

        else:
            logger.debug(f"Currently good, so behaving correctly")
            await super()._send_result(dest, message_response)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='challenge-reponse always bad')
    parser.add_argument('--approach', type=str, choices=MISBEHAVE_CHOICES + ["random"], required=True, help='How will this application misbehave')
    parser.add_argument('--duration', type=float, required=True, help='How long will this application misbehave for in seconds')
    parser.add_argument('--fake-app-restart-period', type=float, required=False, default=None,
                        help='How long to wait for a fake application restart after becoming good again')
    parser.add_argument('--fake-srvr-restart-period', type=float, required=False, default=None,
                        help='How long to wait for a fake server restart after becoming good again')
    args = parser.parse_args()

    client = RoutingClientBad(args.approach, args.duration, args.fake_app_restart_period, args.fake_srvr_restart_period)

    client_common.main(NAME, client)
