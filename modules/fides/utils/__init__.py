def bound(value, low, high):
    if value < low:
        return low
    elif value > high:
        return high
    else:
        return value
