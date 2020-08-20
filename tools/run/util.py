from datetime import datetime, timezone
from threading  import Thread
import subprocess
import sys

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
                    f.write(now + " # " + line)
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
