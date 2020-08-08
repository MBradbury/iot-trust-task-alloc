#!/usr/bin/env python3

import logging
import random
import asyncio

from challenge_response import ChallengeResponseClient as ChallengeResponseClientGood
import client_common

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app-challenge-response-bad")
logger.setLevel(logging.DEBUG)

MISBEHAVE_CHOICES = ["bad-response", "no-response"]

class ChallengeResponseClientBad(ChallengeResponseClientGood):
    def __init__(self, approach, duration):
        super().__init__()

        self.approach = approach
        self.duration = duration

        # Start off being good
        self.is_bad = False

    async def start(self):
        await super().start()

        if self.duration == float('inf'):
            # Always bad
            self.is_bad = True
        else:
            asyncio.create_task(self._periodic())

        logger.info(f"Becoming {'bad' if self.is_bad else 'good'}")

    async def _periodic(self):
        while True:
            await asyncio.sleep(self.duration)

            self.is_bad = not self.is_bad

            logger.info(f"Becoming {'bad' if self.is_bad else 'good'}")


    async def _send_result(self, dest, message_response):
        if self.is_bad:
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
                # A bad message response
                message_response = (b'', 0)
                await self._write_task_result(dest, message_response)

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
    args = parser.parse_args()

    client = ChallengeResponseClientBad(args.approach, args.duration)

    client_common.main("cr", client)
