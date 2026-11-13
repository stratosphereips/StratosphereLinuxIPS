"""Check native app branding, cached builds and safe preparation failures."""

import plistlib
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from slips_files.core.helpers.macos_notifications import mac_notifications
from tests.module_factory import ModuleFactory


def test_notification_app_path_uses_user_application_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the app where macOS can retain its notification identity.

    Parameters:
        monkeypatch: Replace configuration with an isolated relative location.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr(mac_notifications.Path, "home", lambda: Path("output/notification-test"))
    assert mac_notifications.notification_app_path() == Path("output/notification-test/Applications/Slips Notifications.app")


@pytest.mark.parametrize("failure", ["none", "compiler", "missing_tool"])
def test_mac_app_build_is_cached_signed_and_preserves_ready_app_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    """Build once with the Slips icon and keep the old app if an upgrade fails.

    Parameters:
        tmp_path: Isolated source files and app bundle.
        monkeypatch: Stub platform tools while retaining real bundle assembly.
        failure: Successful repeat or upgrade failure to simulate.
    """
    _factory = ModuleFactory()
    source = tmp_path / "helper.swift"
    logo = tmp_path / "logo.png"
    source.write_text("source-v1")
    logo.write_bytes(b"logo")
    app = tmp_path / "notifications/Slips.app"
    monkeypatch.setattr(mac_notifications, "SOURCE", source)
    monkeypatch.setattr(mac_notifications, "LOGO", logo)
    monkeypatch.setattr(mac_notifications, "notification_app_path", lambda: app)
    monkeypatch.setattr(mac_notifications.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mac_notifications.shutil, "which", lambda name: name)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        """Produce build outputs while checking platform argument handling.

        Parameters:
            command: Platform command arguments.
            kwargs: Explicit subprocess limits.

        Returns:
            Successful platform result.
        """
        assert kwargs["check"] is True
        assert kwargs["timeout"] in {10, 60}
        if command[0] == "swiftc":
            Path(command[command.index("-o") + 1]).write_bytes(b"compiled")
        elif command[0] == "sips":
            Path(command[-1]).write_bytes(b"icon")
        elif command[0] == "codesign":
            bundle = Path(command[-1])
            with (bundle / "Contents/Info.plist").open("rb") as handle:
                info = plistlib.load(handle)
            assert info["CFBundleIdentifier"] == mac_notifications.BUNDLE_ID
            assert info["CFBundleDisplayName"] == "Slips"
            assert info["CFBundleIconFile"] == "Slips.icns"
            assert info["LSUIElement"] is True
        return subprocess.CompletedProcess(command, 0)

    runner = Mock(side_effect=run)
    monkeypatch.setattr(mac_notifications.subprocess, "run", runner)
    assert mac_notifications.build_notification_app() == app
    assert runner.call_count == 3
    assert mac_notifications.build_notification_app() == app
    assert runner.call_count == 3
    original = (app / "Contents/Resources/build.sha256").read_text()
    if failure != "none":
        source.write_text("source-v2")
        if failure == "compiler":
            runner.side_effect = subprocess.CalledProcessError(1, "swiftc", stderr="compile failed")
        else:
            monkeypatch.setattr(mac_notifications.shutil, "which", lambda _: None)
        assert mac_notifications.build_notification_app() is None
        assert (app / "Contents/MacOS/SlipsNotification").read_bytes() == b"compiled"
        assert (app / "Contents/Resources/build.sha256").read_text() == original


def test_non_mac_platform_does_not_build_notification_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep macOS preparation away from Linux and Raspberry Pi startup.

    Parameters:
        monkeypatch: Simulate Linux and observe subprocess calls.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr(mac_notifications.platform, "system", lambda: "Linux")
    runner = Mock()
    monkeypatch.setattr(mac_notifications.subprocess, "run", runner)
    assert mac_notifications.build_notification_app() is None
    runner.assert_not_called()


def test_builder_keeps_an_unrelated_existing_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse to replace another application with a matching folder name.

    Parameters:
        tmp_path: Isolated application directory.
        monkeypatch: Substitute the source assets and platform.
    """
    _factory = ModuleFactory()
    app = tmp_path / "Slips Notifications.app"
    (app / "Contents").mkdir(parents=True)
    info = app / "Contents/Info.plist"
    original = plistlib.dumps({"CFBundleIdentifier": "example.another-app"})
    info.write_bytes(original)
    monkeypatch.setattr(mac_notifications, "notification_app_path", lambda: app)
    monkeypatch.setattr(mac_notifications.platform, "system", lambda: "Darwin")
    runner = Mock()
    monkeypatch.setattr(mac_notifications.subprocess, "run", runner)
    assert mac_notifications.build_notification_app() is None
    assert info.read_bytes() == original
    runner.assert_not_called()


@pytest.mark.parametrize("ready,fails", [(False, False), (True, False), (True, True)])
def test_permission_preparation_handles_missing_apps_and_denial(
    monkeypatch: pytest.MonkeyPatch, ready: bool, fails: bool,
) -> None:
    """Request permission only after a build without failing detection.

    Parameters:
        monkeypatch: Replace native app preparation and permission calls.
        ready: Whether a branded helper is ready.
        fails: Whether authorization fails or times out.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr(mac_notifications, "build_notification_app", lambda: Path("output/Slips.app") if ready else None)
    runner = Mock(side_effect=subprocess.TimeoutExpired("notifier", 65) if fails else None)
    monkeypatch.setattr(mac_notifications.subprocess, "run", runner)
    mac_notifications.prepare_notification_app()
    assert runner.call_count == int(ready)
