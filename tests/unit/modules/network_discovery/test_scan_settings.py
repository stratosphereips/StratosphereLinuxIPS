"""Configuration errors must fail clearly before scan analysis starts."""

from unittest.mock import Mock

import pytest

from modules.network_discovery.scan_settings import ScanSettings
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("option,value", [
    ("horizontal_fast_min_targets", 0),
    ("horizontal_fast_min_targets", 10.1),
    ("horizontal_fast_window_seconds", float("nan")),
    ("horizontal_min_failure_ratio", 0.1),
    ("horizontal_max_groups", True),
    ("horizontal_max_targets", 10),
    ("horizontal_slow_window_seconds", 1),
    ("horizontal_alert_cooldown_seconds", "300"),
])
def test_invalid_limits_fail_clearly(option: object, value: object) -> None:
    """Verify invalid limits fail clearly.

    Parameters:
        option: Parameterized scenario value.
        value: Parameterized scenario value.
    """
    factory = ModuleFactory()
    with pytest.raises(ValueError):
        factory.create_horizontal_portscan_obj(**{option: value})


def test_config_defaults_and_overrides() -> None:
    """Verify config defaults and overrides."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    conf = Mock()
    conf.read_configuration.side_effect = lambda section, name, default: 50 if name == "horizontal_fast_min_targets" else default
    settings = ScanSettings.from_config(conf)
    assert settings.horizontal_fast_min_targets == 50
    assert settings.horizontal_slow_min_targets == module.settings.horizontal_slow_min_targets
    assert all(c.args[0] == "network_discovery" for c in conf.read_configuration.call_args_list)


def test_fractional_periods_and_loaded_yaml_defaults() -> None:
    """Verify fractional periods and loaded yaml defaults."""
    module = ModuleFactory().create_horizontal_portscan_obj(horizontal_fast_window_seconds=1.5)
    from pathlib import Path
    import yaml
    options = yaml.safe_load(Path('config/slips.yaml').read_text())['network_discovery']
    settings = ScanSettings(**options)
    settings.validate()
    assert settings == ScanSettings()
    assert module.settings.horizontal_fast_window_seconds == 1.5
