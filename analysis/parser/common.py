from __future__ import annotations

import re
from datetime import datetime
import sys

# 7-bit C1 ANSI sequences
ansi_escape = re.compile(r'''
    \x1B  # ESC
    (?:   # 7-bit C1 Fe (except CSI)
        [@-Z\\-_]
    |     # or [ for CSI, followed by a control sequence
        \[
        [0-?]*  # Parameter bytes
        [ -/]*  # Intermediate bytes
        [@-~]   # Final byte
    )
''', re.VERBOSE)

contiki_log = re.compile(r"\[(.+)\:(.+)\] (.*)")

def parse_contiki_debug(line: str) -> Tuple[str, str, str]:
    # Remove colour escape sequences from the line
    line = ansi_escape.sub('', line)

    m = contiki_log.match(line)
    if m is None:
        return None

    m_log_level = m.group(1).strip()
    m_module = m.group(2).strip()
    m_rest = m.group(3).strip()

    return (m_log_level, m_module, m_rest)

SKIP_LINES = {
    "Serial port disconnected, waiting to get reconnected...",
    "Try to reconnect to /dev/ttyACM0 again...",
    "Reconnected to serial port /dev/ttyACM0",
}

def parse_contiki(f, throw_on_error=True):
    saved_time = None
    saved_line = None

    for (i, line) in enumerate(f):
        try:
            time, rest = line.strip().split(" # ", 1)
        except ValueError as ex:
            if throw_on_error:
                raise
            else:
                print(line)
                print(ex)
                continue
        
        if rest in SKIP_LINES:
            print(f"Skipping line '{rest}'", file=sys.stderr)
            continue

        result = parse_contiki_debug(rest)
        if result is None:
            if saved_line is not None:
                saved_line = (saved_line[0], saved_line[1], saved_line[2] + "\n" + rest)
            else:
                # If the first line was bad, there may have been some initial corruption
                # Skip it and continue onwards
                if i == 0:
                    print(f"Something went wrong with '{line}' in {f}, skipping as it is the first line", file=sys.stderr)
                else:
                    if throw_on_error:
                        raise RuntimeError(f"Something went wrong with '{line}' in {f}")
                    else:
                        print(f"Something went wrong with '{line}' in {f}", file=sys.stderr)
                        continue
        else:
            if saved_line is not None:
                yield (datetime.fromisoformat(saved_time),) + saved_line
            saved_time = time
            saved_line = result

    if saved_line is not None:
        yield (datetime.fromisoformat(saved_time),) + saved_line
