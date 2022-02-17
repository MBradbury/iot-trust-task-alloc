#!/usr/bin/env python3

import argparse
import time
from pathlib import Path

from tools.run import supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import TermApplicationRunner
from tools.keygen.util import eui64_to_ipv6

class ProfileRunner(TermApplicationRunner):
    log_name = "profile"

    def run(self):
        print(f"CWD: {Path.cwd()}", flush=True)
        print(f"Logging motelist to {self.motelist_log_path}", flush=True)
        print(f"Logging flash to {self.flash_log_path}", flush=True)
        print(f"Logging pyterm to {self.pyterm_log_path}", flush=True)

        self.run_motelist()

        time.sleep(0.1)

        self.run_config()

        time.sleep(0.1)

        device_firmware_dir = str(eui64_to_ipv6(self.device.eui64)).replace(":", "_")
        firmware_path = f"{device_firmware_dir}/profile.bin"

        self.run_flash(firmware_path)

        time.sleep(0.1)

        self.run_pyterm()

parser = argparse.ArgumentParser(description='Profile runner')
parser.add_argument('--log-dir', type=Path, default=DEFAULT_LOG_DIR, help='The directory to store log output')
parser.add_argument("--firmware-type",
                    choices=supported_firmware_types,
                    default=supported_firmware_types[0],
                    help="The OS that was used to create the firmware.")
args = parser.parse_args()

runner = ProfileRunner(args.log_dir, args.firmware_type)
runner.run()
