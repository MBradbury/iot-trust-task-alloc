from datetime import datetime, timezone
from threading  import Thread
import subprocess
import sys
import os
from pathlib import Path
import shlex

from common.configuration import devices
from common.configuration_common import DeviceKind

from resource_rich.monitor.monitor_impl import MonitorBase

# From: https://stackoverflow.com/questions/4984428/python-subprocess-get-childrens-output-to-file-and-terminal
class Teed:
    def __init__(self):
        self.threads = []

    def add(self, p, stdout=None, stderr=None):
        if stdout is not None:
            self._tee(p.stdout, stdout)

        if stderr is not None:
            self._tee(p.stderr, stderr)

    def wait(self):
        for t in self.threads:
            t.join()

    def _tee(self, infile, files):
        """Print `infile` to `files` in a separate thread."""
        def fanout(infile, files):
            for line in iter(infile.readline, ''):
                now = datetime.now(timezone.utc).isoformat()

                for f in files:
                    f.write(f"{now} # {line}")
                    f.flush()

                    if getattr(f, "stop_further_processing", False):
                        break

        t = Thread(target=fanout, args=(infile, files))
        t.daemon = True
        t.start()
        self.threads.append(t)

class StreamNoTimestamp:
    def __init__(self, stream):
        self.stream = stream

    def write(self, line: str):
        ts, line = line.split(" # ", 1)

        self.stream.write(line)

    def flush(self):
        self.stream.flush()

    def close(self):
        pass

def Popen(*args, **kwargs):
    print(args, kwargs, flush=True)
    return subprocess.Popen(*args, **kwargs)

class ApplicationRunner:
    def __init__(self, log_dir: Path, firmware_type: str):
        self.hostname = os.uname()[1]
        self.log_dir = log_dir
        self.firmware_type = firmware_type

        self.set_log_paths()

        self.device = self.get_device()

    def set_log_paths(self):
        self.log_dir = self.log_dir.expanduser()

        # Create log dir if it does not exist
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.motelist_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.motelist.log"
        self.flash_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.flash.log"

    def get_device(self):
        # Get the device connected to this host
        devices_for_host = [dev for dev in devices if dev.hostname == self.hostname]
        if not devices_for_host:
            raise RuntimeError(f"No devices configured for this host {self.hostname} in the configuration")
        if len(devices_for_host) > 1:
            raise RuntimeError(f"More than one device configured for this host {self.hostname} in the configuration")

        (device,) = devices_for_host

        return device

    def run_motelist(self):
        with open(self.motelist_log_path, 'w') as motelist_log:
            teed = Teed()
            motelist = Popen(
                shlex.split(f"python3 -m tools.deploy.motelist --mote-type {self.device.kind.value}"),
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            self.record_pid(motelist.pid)
            teed.add(motelist,
                     stdout=[motelist_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[motelist_log, StreamNoTimestamp(sys.stderr)])
            teed.wait()
            motelist.wait()

            if motelist.returncode != 0:
                raise RuntimeError("Motelist failed")

    def run_flash(self, firmware_path: str):
        firmware_path = Path.cwd() / 'setup' / firmware_path

        with open(self.flash_log_path, 'w') as flash_log:
            teed = Teed()
            flash = Popen(
                shlex.split(f"python3 flash.py '{self.device.identifier}' '{firmware_path}' {self.device.kind.value} {self.firmware_type}"),
                cwd="tools/deploy",
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            self.record_pid(flash.pid)
            teed.add(flash,
                     stdout=[flash_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[flash_log, StreamNoTimestamp(sys.stderr)])
            teed.wait()
            flash.wait()
            
            if flash.returncode != 0:
                raise RuntimeError("Flashing failed")
            else:
                print("Flashing finished!", flush=True)

    def run(self):
        raise NotImplementedError()

    def record_pid(self, pid: int):
        with open("pidfile", "a+") as pidfile:
            print(str(pid), file=pidfile)

class TermApplicationRunner(ApplicationRunner):
    def set_log_paths(self):
        super().set_log_paths()

        self.pyterm_log_path = self.log_dir / f"{self.log_name}.{self.hostname}.pyterm.log"

    def run_pyterm(self):
        with open(self.pyterm_log_path, 'w') as pyterm_log, \
         MonitorBase(f"{self.log_name}.{self.hostname}", log_dir=self.log_dir) as pcap_monitor:
            teed = Teed()

            # stdin=subprocess.PIPE is needed in order to ensure that a stdin handle exists.
            # This is because this script may be called under nohup in which case stdin won't exist.
            pyterm = Popen(
                shlex.split(f"python3 -m tools.deploy.term {self.device.identifier} {self.device.kind.value} --log-dir {self.log_dir}"),
                #shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                universal_newlines=True,
                encoding="utf-8",
            )
            self.record_pid(pyterm.pid)
            teed.add(pyterm,
                     stdout=[pcap_monitor, pyterm_log, StreamNoTimestamp(sys.stdout)],
                     stderr=[pcap_monitor, pyterm_log, StreamNoTimestamp(sys.stderr)])
            teed.wait()
            pyterm.wait()
            
            if pyterm.returncode != 0:
                raise RuntimeError("pyterm failed")
            else:
                print("pyterm finished!", flush=True)
