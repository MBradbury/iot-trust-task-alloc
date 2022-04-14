from datetime import datetime
import re
import ipaddress
import ast
from dataclasses import dataclass

@dataclass(frozen=True)
class Task:
    dt: datetime
    source: ipaddress.IPv6Address
    payload: object
    application: str

class EdgeAnalyser:
    RE_RECEIVE_TASK = re.compile(r"Received task at (.+) from (.+) <payload=(.+)>")
    RE_RECEIVE_TASK2 = re.compile(r"Received message at (.+) from (.+) <(.+)>")

    RE_BECOMING = re.compile(r"[a-z]+ becoming (good|bad)")
    RE_CURRENTLY = re.compile(r"Currently (good|bad), so behaving (correctly|incorrectly with ([A-Za-z-]+))")

    def __init__(self, hostname: str):
        self.hostname = hostname

        self.start_times = []

        # For bad applications, there will be times at which the system misbehaves
        self.behaviour_changes = []
        self.task_actions = []

        self.received_tasks = []

    def analyse(self, f):
        for line in f:
            try:
                time, rest = line.strip().split(" # ", 1)

                time = datetime.fromisoformat(time)

                level, app, rest = rest.split(":", 2)

                self.analyse_line(time, level, app, rest)

            except ValueError as ex:
                print(ex)
                print(time, line)
                break

    def analyse_line(self, time, level, app, rest):
        if rest.startswith("Starting"):
            self._process_starting(time, level, app, rest)
        elif "becoming" in rest:
            self._process_becoming(time, level, app, rest)
        elif rest.startswith("Currently"):
            self._process_currently(time, level, app, rest)
        elif rest.startswith("Received task"):
            self._process_received_task(time, level, app, rest)
        elif rest.startswith("Received message"):
            self._process_received_task2(time, level, app, rest)
        else:
            print(f"Unknown line contents '{rest}' at {time}")

    def _process_starting(self, time: datetime, level: str, app: str, line: str):
        self.start_times.append(time)

    def _process_becoming(self, time: datetime, level: str, app: str, line: str):
        """When changing from behaving well or not"""
        m = self.RE_BECOMING.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_behaviour = m.group(1) == "good"

        self.behaviour_changes.append((time, m_behaviour))

    def _process_currently(self, time: datetime, level: str, app: str, line: str):
        """How the application misbehaves"""
        m = self.RE_CURRENTLY.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_behaviour = m.group(1) == "good"
        m_action = m.group(2) == "correctly"
        m_action_type = m.group(3)

        self.task_actions.append((time, m_behaviour, m_action, m_action_type))

    def _process_received_task(self, time: datetime, level: str, app: str, line: str):
        m = self.RE_RECEIVE_TASK.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_dt = datetime.fromisoformat(m.group(1))
        m_from = ipaddress.IPv6Address(m.group(2))
        m_payload = ast.literal_eval(m.group(3))

        task = Task(m_dt, m_from, m_payload, app)

        self.received_tasks.append(task)

    def _process_received_task2(self, time: datetime, level: str, app: str, line: str):
        m = self.RE_RECEIVE_TASK2.match(line)
        if m is None:
            raise RuntimeError(f"Failed to parse '{line}'")

        m_dt = datetime.fromisoformat(m.group(1))
        m_from = ipaddress.IPv6Address(m.group(2))
        m_payload = m.group(3)

        task = Task(m_dt, m_from, m_payload, app)

        self.received_tasks.append(task)
