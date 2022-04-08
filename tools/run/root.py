#!/usr/bin/env python3

import argparse
import subprocess
import time
import sys
from pathlib import Path
import shlex

from tools.deploy.motedev import get_mote_device
from tools.run import supported_firmware_types, DEFAULT_LOG_DIR
from tools.run.util import Teed, Popen, StreamNoTimestamp, ApplicationRunner

class RootRunner(ApplicationRunner):
    log_name = "root"

    def __init__(self, log_dir: Path, firmware_type: str, no_flush_oscore: bool, mode: str):
        super().__init__(log_dir, firmware_type)
        self.no_flush_oscore = no_flush_oscore
        self.mode = mode

    def set_log_paths(self):
        super().set_log_paths()

        self.tunslip_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.tunslip.log"
        self.service_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.service.log"
        self.root_server_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.root_server.log"

    def run_flush_oscore(self):
        # By default we need to remove the OSCORE state storing the cached sequence numbers
        if not self.no_flush_oscore:
            print("Removing cached OSCORE state", flush=True)

            remove_files = ["sequence.json", "lock"]

            oscore_contexts_dir = Path("resource_rich/root/keystore/oscore-contexts")
            for content in oscore_contexts_dir.iterdir():
                for remove_file in remove_files:
                    sequence = content / remove_file
                    print(f"Removing {sequence}", flush=True)
                    sequence.unlink(missing_ok=True)

    def _start_local_border_router_service(self):
        com_port = get_mote_device(self.device.identifier, self.device.kind.value)
        print(f"Found com port {com_port} for device {self.device}", flush=True)

        if self.mode == "slip":
            command = f"sudo ./tunslip6 -v3 -s '{com_port}' fd00::1/64"
            cwd = Path("~/deploy/contiki-ng/tools/serial-io").expanduser()
        elif self.mode == "native":
            command = f"sudo ./border-router.native -v3 -s '{com_port}' fd00::1/64"
            cwd = Path("~/deploy/contiki-ng/examples/rpl-border-router").expanduser()
        else:
            raise RuntimeError(f"Unknown border router mode {self.mode}")

        br = Popen(
            shlex.split(command),
            cwd=cwd,
            #shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding="utf-8",
            errors="backslashreplace",
        )
        self.record_pid(br.pid)
        return br

    def run_root_server(self):
        with open(self.tunslip_log_path, 'w') as tunslip_log, \
             open(self.service_log_path, 'w') as service_log, \
             open(self.root_server_log_path, 'w') as root_server_log:

            teed = Teed()

            tunslip = self._start_local_border_router_service()
            teed.add(tunslip,
                     stdout=[tunslip_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[tunslip_log, StreamNoTimestamp(sys.stderr)])

            time.sleep(2)

            service = Popen(
                shlex.split("sudo service mosquitto restart"),
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            teed.add(service,
                     stdout=[service_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[service_log, StreamNoTimestamp(sys.stderr)])
            service.wait()
            if service.returncode != 0:
                raise RuntimeError("mosquitto restart failed")
            else:
                print("mosquitto restart finished!", flush=True)

            time.sleep(2)

            root_server = Popen(
                shlex.split("python3 -m resource_rich.root.root_server -k resource_rich/root/keystore"),
                cwd=Path("~/deploy/iot-trust-task-alloc").expanduser(),
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            self.record_pid(root_server.pid)
            teed.add(root_server,
                     stdout=[root_server_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[root_server_log, StreamNoTimestamp(sys.stderr)])

            teed.wait()
            root_server.wait()
            tunslip.wait()

    def run(self):
        print(f"CWD: {Path.cwd()}", flush=True)
        print(f"Logging motelist to {self.motelist_log_path}", flush=True)
        print(f"Logging flash to {self.flash_log_path}", flush=True)
        print(f"Logging tunslip to {self.tunslip_log_path}", flush=True)
        print(f"Logging service to {self.service_log_path}", flush=True)
        print(f"Logging root_server to {self.root_server_log_path}", flush=True)

        self.run_motelist()

        time.sleep(0.1)

        if self.mode == "slip":
            self.run_flash("border-router.bin")
        elif self.mode == "native":
            self.run_flash("slip-radio.bin")
        else:
            raise RuntimeError(f"Unknown border router mode {self.mode}")

        time.sleep(0.1)

        self.run_flush_oscore()

        time.sleep(0.1)

        self.run_root_server()

parser = argparse.ArgumentParser(description='Root runner')
parser.add_argument('--log-dir', type=Path, default=DEFAULT_LOG_DIR, help='The directory to store log output')
parser.add_argument("--firmware-type",
                    choices=supported_firmware_types,
                    default=supported_firmware_types[0],
                    help="The OS that was used to create the firmware.")
parser.add_argument("--no-flush-oscore", action="store_true", default=False, help="Disable flushing OSCORE cache")
parser.add_argument("--mode", choices=["native", "slip"], default="slip", help="The mode in which to run the border router")
args = parser.parse_args()

runner = RootRunner(args.log_dir, args.firmware_type, args.no_flush_oscore, mode=args.mode)
runner.run()
