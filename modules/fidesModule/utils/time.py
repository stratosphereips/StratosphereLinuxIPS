import time

Time = float
"""Type for time used across the whole module. 

Represents the current time in seconds since the Epoch. Can have frictions of seconds.

We have it as alias so we can easily change that in the future.
"""


def now() -> Time:
    """Returns current Time."""
    return time.time()
