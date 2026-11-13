"""Build a locally signed macOS notification app with the Slips identity."""

import fcntl
import hashlib
import logging
import platform
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path

BUNDLE_ID = "org.stratosphereips.slips.notifications"
SOURCE = Path(
    "slips_files/core/helpers/macos_notifications/slips_notification.swift"
)
LOGO = Path("modules/web_interface/slips-logo.png")


def notification_app_path() -> Path:
    """Locate the notification app in the desktop user's Applications directory.

    Returns:
        Stable app bundle registered with macOS across Slips runs.
    """
    return Path.home() / "Applications" / "Slips Notifications.app"


def build_notification_app() -> Path | None:
    """Prepare the native app once, keeping compilation outside alert handling.

    Returns:
        Ready app bundle, or None if native preparation is unavailable.
    """
    if platform.system() != "Darwin":
        return None
    app = notification_app_path()
    try:
        fingerprint = hashlib.sha256(
            SOURCE.read_bytes()
            + LOGO.read_bytes()
            + Path(__file__).read_bytes()
            + platform.machine().encode()
        ).hexdigest()
        app.parent.mkdir(parents=True, exist_ok=True)
        with (app.parent / ".slips-notification-build.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if app.exists():
                with (app / "Contents/Info.plist").open("rb") as handle:
                    if (
                        plistlib.load(handle).get("CFBundleIdentifier")
                        != BUNDLE_ID
                    ):
                        raise OSError(
                            "The notification app path belongs to another application."
                        )
            marker = app / "Contents" / "Resources" / "build.sha256"
            if (
                marker.exists()
                and marker.read_text() == fingerprint
                and all(
                    (app / name).is_file()
                    for name in (
                        "Contents/MacOS/SlipsNotification",
                        "Contents/Resources/Slips.icns",
                    )
                )
            ):
                return app
            tools = {
                name: shutil.which(name)
                for name in ("swiftc", "sips", "codesign")
            }
            if not all(tools.values()):
                logging.getLogger(__name__).warning(
                    "Slips notification logo requires the macOS command-line developer tools."
                )
                return None
            with tempfile.TemporaryDirectory(
                prefix=".slips-notification-build-", dir=app.parent
            ) as directory:
                staged = Path(directory) / "Slips.app"
                contents = staged / "Contents"
                binary = contents / "MacOS" / "SlipsNotification"
                resources = contents / "Resources"
                binary.parent.mkdir(parents=True)
                resources.mkdir()
                commands = [
                    [
                        tools["swiftc"],
                        str(SOURCE),
                        "-o",
                        str(binary),
                        "-framework",
                        "AppKit",
                        "-framework",
                        "UserNotifications",
                    ],
                    [
                        tools["sips"],
                        "-s",
                        "format",
                        "icns",
                        str(LOGO),
                        "--out",
                        str(resources / "Slips.icns"),
                    ],
                ]
                for command in commands:
                    subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=60,
                    )
                with (contents / "Info.plist").open("wb") as handle:
                    plistlib.dump(
                        {
                            "CFBundleIdentifier": BUNDLE_ID,
                            "CFBundleName": "Slips",
                            "CFBundleDisplayName": "Slips",
                            "CFBundleExecutable": "SlipsNotification",
                            "CFBundleIconFile": "Slips.icns",
                            "CFBundlePackageType": "APPL",
                            "CFBundleVersion": "1",
                            "CFBundleShortVersionString": "1.0",
                            "LSUIElement": True,
                            "NSPrincipalClass": "NSApplication",
                            "LSMinimumSystemVersion": "10.14",
                        },
                        handle,
                    )
                (resources / "build.sha256").write_text(fingerprint)
                subprocess.run(
                    [
                        tools["codesign"],
                        "--force",
                        "--sign",
                        "-",
                        "--identifier",
                        BUNDLE_ID,
                        "--requirements",
                        f'=designated => identifier "{BUNDLE_ID}"',
                        str(staged),
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                previous = app.parent / ".slips-notification-previous.app"
                if previous.exists():
                    shutil.rmtree(previous)
                if app.exists():
                    app.rename(previous)
                try:
                    staged.rename(app)
                except OSError:
                    if previous.exists():
                        previous.rename(app)
                    raise
                if previous.exists():
                    shutil.rmtree(previous)
                return app
    except (
        OSError,
        ValueError,
        plistlib.InvalidFileException,
        subprocess.SubprocessError,
    ) as error:
        detail = getattr(error, "stderr", None) or str(error)
        logging.getLogger(__name__).warning(
            "Unable to prepare Slips notifications: %s", detail.strip()
        )
        return None


def prepare_notification_app() -> None:
    """Build and request native permission in the background for enabled popups."""
    app = build_notification_app()
    if app is None:
        return
    try:
        subprocess.run(
            ["open", "-g", "-n", str(app), "--args", "--authorize"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        logging.getLogger(__name__).warning(
            "Slips notification permission: %s", detail.strip()
        )


if __name__ == "__main__":
    raise SystemExit(0 if build_notification_app() else 1)
