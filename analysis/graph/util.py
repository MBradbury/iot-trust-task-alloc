
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
