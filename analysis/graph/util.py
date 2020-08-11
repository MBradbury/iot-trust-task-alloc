
from analysis.parser.wsn_pyterm import ChallengeResponseType

def squash_true_false_seq(XY):
    """Return two lists containing a sequence of pairs of datetimes for which the value was true and false"""

    true_start = None
    false_start = None

    true_list = []
    false_list = []

    for (time, v) in XY:
        if v:
            # Transition from false to true
            if false_start is not None:
                false_list.append((false_start, time - false_start))
                false_start = None

            if true_start is None:
                true_start = time
        else:
            # Transition from true to false
            if true_start is not None:
                true_list.append((true_start, time - true_start))
                true_start = None

            if false_start is None:
                false_start = time

    # Transition from true to false
    if true_start is not None:
        true_list.append((true_start, time - true_start))
        true_start = None

    # Transition from false to true
    if false_start is not None:
        false_list.append((false_start, time - false_start))
        false_start = None

    return true_list, false_list

def squash_generic_seq(XY, kinds):
    """Return two lists containing a sequence of pairs of datetimes for which the value was true and false"""

    start = {kind: None for kind in kinds}
    result = {kind: list() for kind in kinds}

    #true_start = None
    #false_start = None

    #true_list = []
    #false_list = []

    for (time, v) in XY:
        # Transition from false to true
        # Find only other kind that is not none
        other_starts = [kind for (kind, s) in start.items() if s is not None]
        if len(other_starts) == 1:
            (k,) = other_starts

            result[k].append((start[k], time - start[k]))
            start[k] = None

        elif len(other_starts) > 1:
            raise RuntimeError("Logic error")

        if start[v] is None:
            start[v] = time

    other_starts = [kind for (kind, s) in start.items() if s is not None]
    if len(other_starts) == 1:
        (k,) = other_starts

        result[k].append((start[k], time - start[k]))
        start[k] = None

    elif len(other_starts) > 1:
        raise RuntimeError("Logic error")

    return result

def ChallengeResponseType_to_shape_and_color(c: ChallengeResponseType):
    if c == ChallengeResponseType.NO_ACK:
        return ("X", "#1f77b4")

    elif c == ChallengeResponseType.TIMEOUT:
        return ("o", "#ff7f0e")

    elif c == ChallengeResponseType.RESPONSE:
        return ("*", "#2ca02c")

    else:
        raise RuntimeError(f"Unknown value {c}")
