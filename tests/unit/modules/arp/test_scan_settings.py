"""Validate the ARP scan configuration without starting Slips."""

from unittest.mock import Mock
import pytest

from modules.arp.scan_settings import ARPScanSettings
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("name,value", [("scan_window_seconds", 0), ("scan_window_seconds", float("nan")),
    ("scan_min_targets", True), ("scan_max_sources", 1.5), ("scan_min_unfamiliar_ratio", 1.1),
    ("scan_min_unfamiliar_ratio", "0.8"), ("scan_max_targets", 10), ("scan_broad_targets", 9),
    ("scan_checkpoint_seconds", 0), ("scan_max_relationships", 0)])
def test_invalid_settings_fail_clearly(name: str, value: object) -> None:
    """Reject invalid limits and inconsistent counts.

    Parameters:
        name: Configuration key.
        value: Invalid field value.
    """
    factory = ModuleFactory()
    with pytest.raises(ValueError):
        factory.create_arp_scan_detector(**{name: value})


def test_configuration_reads_arp_section_and_defaults() -> None:
    """Read custom values from the module section while retaining safe defaults."""
    _factory = ModuleFactory()
    conf = Mock()
    conf.read_configuration.side_effect = lambda section, name, default: 60 if name == "scan_window_seconds" else default
    settings = ARPScanSettings.from_config(conf)
    assert settings.scan_window_seconds == 60
    assert settings.scan_min_unfamiliar_targets == 10
    assert all(call.args[0] == "arp" for call in conf.read_configuration.call_args_list)
