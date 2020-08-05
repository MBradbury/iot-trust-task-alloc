from enum import Enum, Flag, auto

# 0. Send task request from rc to rr
# 1. rr acks task resquest (can fail)
# 2. rr sends task response (can fail)
# 3. rc validates task response (can fail)

class Activity(Flag):
    TASK_SUBMISSION_ACK = auto()
    TASK_RESPONSE = auto()
    TASK_QUALITY = auto()


class Observation(Enum):
    def __new__(cls, good, short_name, activity):
        """Auto-incrementing values and stores the 'goodness' of the observation"""
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        obj.good = good
        obj.short_name = short_name
        obj.activity = activity
        return obj

    def __init__(self, good, short_name, activity):
        self.good = good
        self.short_name = short_name
        self.activity = activity

    # 1 failed
    TASK_SUBMISSION_ACK_TIMEDOUT = (False, "ACK-TIMEOUT", Activity.TASK_SUBMISSION_ACK)

    # 1 succeeded and 2 failed
    TASK_RESPONSE_TIMEDOUT = (False, "RESP-TIMEOUT", Activity.TASK_SUBMISSION_ACK | Activity.TASK_RESPONSE)

    # 1 and 2 succeeded and 3 failed
    TASK_RESULT_QUALITY_INCORRECT = (False, "RES-BAD", Activity.TASK_SUBMISSION_ACK | Activity.TASK_RESPONSE | Activity.TASK_QUALITY)

    # 1, 2 and 3 succeeded
    TASK_RESULT_QUALITY_CORRECT = (True, "RES-GOOD", Activity.TASK_SUBMISSION_ACK | Activity.TASK_RESPONSE | Activity.TASK_QUALITY)
