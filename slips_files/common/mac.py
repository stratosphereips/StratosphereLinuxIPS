"""Classify IEEE 802 48-bit MAC addresses without network lookups."""

import re


def normalize_mac(value: str | None) -> str:
    """Normalize common MAC notation, including unpadded operating-system octets.

    Parameters:
        value: Colon, hyphen, dotted or compact 48-bit address.

    Returns:
        Lowercase colon-separated address, or an empty string if invalid.
    """
    if not isinstance(value, str):
        return ""
    value = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{12}", value):
        return ":".join(value[index : index + 2] for index in range(0, 12, 2))
    if re.fullmatch(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", value):
        return normalize_mac(value.replace(".", ""))
    for separator in (":", "-"):
        parts = value.split(separator)
        if len(parts) == 6 and all(
            re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts
        ):
            return ":".join(part.zfill(2) for part in parts)
    return ""


def classify_mac(value: str | None) -> str:
    """Read address type and administration bits without inferring randomness.

    Parameters:
        value: Candidate 48-bit MAC address.

    Returns:
        Address classification; local administration does not prove randomness.
    """
    if value is None or value == "":
        return "unknown"
    mac = normalize_mac(value)
    if not mac:
        return "invalid"
    if mac == "00:00:00:00:00:00":
        return "unspecified"
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    first_octet = int(mac[:2], 16)
    if first_octet & 0x01:
        return "multicast"
    return (
        "locally_administered"
        if first_octet & 0x02
        else "universally_administered"
    )
