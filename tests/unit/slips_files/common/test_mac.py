"""Verify MAC administration bits and supported input representations."""

import pytest

from slips_files.common.mac import classify_mac, normalize_mac
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("first_octet", range(256))
def test_mac_bits(first_octet: int) -> None:
    """Check every first octet so group addresses cannot be called randomized.

    Parameters:
        first_octet: All possible I/G and U/L bit combinations.
    """
    _module_factory = ModuleFactory()
    address = f"{first_octet:02x}:d7:7b:fa:6a:55"
    if first_octet % 2:
        expected = "multicast"
    elif first_octet % 4 == 2:
        expected = "locally_administered"
    else:
        expected = "universally_administered"
    assert classify_mac(address) == expected


@pytest.mark.parametrize(
    "value,normalized,kind",
    [
        ("A2:D7:7B:FA:6A:55", "a2:d7:7b:fa:6a:55", "locally_administered"),
        ("a2-d7-7b-fa-6a-55", "a2:d7:7b:fa:6a:55", "locally_administered"),
        ("a2d7.7bfa.6a55", "a2:d7:7b:fa:6a:55", "locally_administered"),
        ("a2d77bfa6a55", "a2:d7:7b:fa:6a:55", "locally_administered"),
        (" d8:58:d7:0:67:11 ", "d8:58:d7:00:67:11", "universally_administered"),
        ("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", "broadcast"),
        ("00:00:00:00:00:00", "00:00:00:00:00:00", "unspecified"),
        ("01:00:5e:00:00:fb", "01:00:5e:00:00:fb", "multicast"),
        ("33:33:00:00:00:fb", "33:33:00:00:00:fb", "multicast"),
        (None, "", "unknown"),
        ("", "", "unknown"),
        ("not-a-mac", "", "invalid"),
        ("a2:d7:7b:fa:6a", "", "invalid"),
        ("a2:d7:7b:fa:6a:555", "", "invalid"),
        ("a2:d7:7b:fa:6a:gg", "", "invalid"),
        ("a2-d7:7b:fa:6a:55", "", "invalid"),
    ],
)
def test_mac_representations(value: str | None, normalized: str, kind: str) -> None:
    """Accept conventional notation and reject missing or malformed addresses.

    Parameters:
        value: User, operating-system or packet address representation.
        normalized: Expected canonical representation, if valid.
        kind: Expected classification.
    """
    _module_factory = ModuleFactory()
    assert normalize_mac(value) == normalized
    assert classify_mac(value) == kind
