#!/usr/bin/env python3

import argparse
from pathlib import Path

from tools.run import supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.edge import EdgeRunner, ApplicationAction

class BadEdgeRunner(EdgeRunner):
    binary_name = "bad_edge.bin"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Edge runner')
    parser.add_argument('--log-dir', type=Path, default=DEFAULT_LOG_DIR, help='The directory to store log output')
    parser.add_argument("--firmware-type",
                        choices=supported_firmware_types,
                        default=supported_firmware_types[0],
                        help="The OS that was used to create the firmware.")

    parser.add_argument("--application", nargs='*', metavar='application-name nice params',
                        action=ApplicationAction,
                        help="The applications to start")

    args = parser.parse_args()

    runner = BadEdgeRunner(args.log_dir, args.firmware_type, args.application)
    runner.run()
