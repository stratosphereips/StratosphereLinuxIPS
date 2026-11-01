"""Interpret Zeek direction evidence without changing recorded endpoints."""


def zeek_history_in_final_direction(history: str) -> str:
    """Express packet flags relative to the endpoints in the final log record.

    Parameters:
        history: Raw Zeek history, including any role-flip markers.

    Returns:
        History with flags before each subsequent flip changing letter case.
    """
    if "^" not in history:
        return history
    parts = history.split("^")
    last = len(parts) - 1
    return "^".join(
        part.swapcase() if (last - index) % 2 else part
        for index, part in enumerate(parts)
    )


def tcp_initiator_is_known(proto: str, history: str | None) -> bool:
    """Require TCP handshake evidence before assigning client/server roles.

    Parameters:
        proto: Transport protocol.
        history: Zeek packet history, or None for inputs without this field.

    Returns:
        Whether direction-sensitive checks can use the recorded originator.
        Other transports and inputs without Zeek history retain their behavior.
    """
    if proto.lower() != "tcp" or history is None:
        return True
    if not isinstance(history, str):
        return False
    history = zeek_history_in_final_direction(history)
    return "S" in history or "h" in history
