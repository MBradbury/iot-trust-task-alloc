from enum import Enum, auto

from models.observations import Observation

class StableModel(Enum):
    ALWAYS_GOOD = auto()
    ALWAYS_BAD_RANDOM = auto()
    ALWAYS_BAD_SUBMIT_ACK = auto()
    ALWAYS_BAD_TASK_RESPONSE = auto()
    ALWAYS_BAD_TASK_QUALITY = auto()

class TaskModel:
    def __init__(self, kind):
        self.kind = kind

    def single_task_observations(self):
        if self.kind == StableModel.ALWAYS_GOOD:
            return Observation.TASK_RESULT_QUALITY_CORRECT

        elif self.kind == StableModel.ALWAYS_BAD_SUBMIT_ACK:
            return Observation.TASK_SUBMISSION_ACK_TIMEDOUT

        elif self.kind == StableModel.ALWAYS_BAD_TASK_RESPONSE:
            return Observation.TASK_RESPONSE_TIMEDOUT

        elif self.kind == StableModel.ALWAYS_BAD_TASK_QUALITY:
            return Observation.TASK_RESULT_QUALITY_INCORRECT

        elif self.kind == StableModel.ALWAYS_BAD_RANDOM:
            return random.choice([
                Observation.TASK_RESULT_QUALITY_CORRECT,
                Observation.TASK_SUBMISSION_ACK_TIMEDOUT,
                Observation.TASK_RESPONSE_TIMEDOUT,
                Observation.TASK_RESULT_QUALITY_INCORRECT
            ])

    def multiple_task_observations(self, n):
        return [
            self.single_task_observations()
            for _ in range(n)
        ]
