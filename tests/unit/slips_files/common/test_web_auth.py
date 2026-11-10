# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the shared web interface session/login helpers."""
import json
import subprocess
import sys
import time
from email.message import Message
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator
from unittest.mock import Mock
from urllib.request import Request

import pytest

from slips_files.common import web_auth
from tests.module_factory import ModuleFactory


@pytest.fixture(autouse=True)
def clear_login_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Give each test a persistent test password hash and clean attempts.

    Parameters:
        tmp_path: Isolated directory for the web password record.
        monkeypatch: Replaces the permanent password path during this test.
    """
    auth_path = tmp_path / "web_auth.json"
    auth_path.write_text(json.dumps({"hash": "ab" * 32}))
    monkeypatch.setattr(web_auth, "get_web_auth_path", Mock(return_value=str(auth_path)))
    monkeypatch.setattr(
        web_auth, "ensure_web_password_matches_redis_password", Mock()
    )
    web_auth._login_attempts.clear()
    yield
    web_auth._login_attempts.clear()


def test_issue_token_validates():
    token = web_auth.issue_token()

    assert web_auth.validate_token(token)


def test_validate_token_rejects_none():
    assert not web_auth.validate_token(None)


def test_validate_token_rejects_malformed_token():
    assert not web_auth.validate_token("not-a-real-token")


def test_validate_token_rejects_expired_token(monkeypatch):
    expiry = int(time.time()) - 10
    mac = web_auth.hmac.new(
        web_auth._session_signing_key(),
        str(expiry).encode(),
        web_auth.sha256,
    ).hexdigest()
    expired_token = f"{expiry}.{mac}"

    assert not web_auth.validate_token(expired_token)


def test_validate_token_rejects_tampered_signature():
    token = web_auth.issue_token()
    expiry_str, _, _ = token.partition(".")

    assert not web_auth.validate_token(f"{expiry_str}.deadbeef")


def test_session_survives_new_web_server_process(tmp_path: Path) -> None:
    """Accept a cookie in a fresh Python process using the same auth file.

    Parameters:
        tmp_path: Isolated persistent password record shared with the child.
    """
    token = web_auth.issue_token()
    auth_path = tmp_path / "web_auth.json"
    script = (
        "import sys\n"
        "from unittest.mock import Mock\n"
        "from slips_files.common import web_auth\n"
        "web_auth.get_web_auth_path = Mock(return_value=sys.argv[1])\n"
        "web_auth.ensure_web_password_matches_redis_password = Mock()\n"
        "print(web_auth.validate_token(sys.argv[2]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(auth_path), token],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == "True"


def test_changing_web_password_invalidates_session(tmp_path: Path) -> None:
    """Reject old cookies when the stored password hash changes.

    Parameters:
        tmp_path: Isolated persistent password record to update.
    """
    token = web_auth.issue_token()
    (tmp_path / "web_auth.json").write_text(
        json.dumps({"hash": "cd" * 32})
    )

    assert not web_auth.validate_token(token)


def test_session_cookie_lasts_one_year() -> None:
    """Keep a browser cookie valid across ordinary Slips restarts."""
    token = web_auth.issue_token()
    expiry = int(token.partition(".")[0])

    assert expiry - time.time() > 364 * 24 * 60 * 60


@pytest.mark.parametrize("same_credentials", [False, True])
def test_session_cookie_names_follow_credentials(
    tmp_path: Path, same_credentials: bool,
) -> None:
    """Keep names stable for copied credentials and distinct for other servers.

    Parameters:
        tmp_path: Separate credential paths for two installations.
        same_credentials: Whether the second path contains a copied password record.
    """
    _factory = ModuleFactory()
    first = web_auth.session_cookie_name()
    other = tmp_path / "other-web-auth.json"
    other.write_text(json.dumps({"hash": ("ab" if same_credentials else "cd") * 32}))
    web_auth.get_web_auth_path.return_value = str(other)
    second = web_auth.session_cookie_name()
    assert (first == second) is same_credentials
    assert first.startswith(web_auth.SESSION_COOKIE_NAME + "_")


@pytest.mark.parametrize("case,expected", [
    ("scoped", True), ("legacy", True), ("both", True),
    ("invalid-scoped-valid-legacy", False), ("foreign", False),
    ("empty", False), ("tampered", False), ("password-changed", False),
])
def test_validate_session_cookies(
    tmp_path: Path, case: str, expected: bool,
) -> None:
    """Accept valid sessions while preserving signature and password checks.

    Parameters:
        tmp_path: Isolated credential record.
        case: Scoped, legacy, foreign, invalid or revoked session.
        expected: Whether the browser may access this installation.
    """
    _factory = ModuleFactory()
    token = web_auth.issue_token()
    name = web_auth.session_cookie_name()
    values = {name: token}
    if case == "legacy":
        values = {web_auth.SESSION_COOKIE_NAME: token}
    elif case == "both":
        values[web_auth.SESSION_COOKIE_NAME] = "another-server-cookie"
    elif case == "invalid-scoped-valid-legacy":
        values = {name: "invalid", web_auth.SESSION_COOKIE_NAME: token}
    elif case == "foreign":
        values = {name + "foreign": token}
    elif case == "empty":
        values = {}
    elif case == "tampered":
        values[name] = token + "changed"
    elif case == "password-changed":
        (tmp_path / "web_auth.json").write_text(json.dumps({"hash": "cd" * 32}))
    assert web_auth.validate_session_cookies(values) is expected


@pytest.mark.parametrize("scoped", [False, True])
def test_browser_logins_on_different_localhost_ports(
    tmp_path: Path, scoped: bool,
) -> None:
    """Reproduce shared browser cookies when another SSH-forwarded page logs in.

    Parameters:
        tmp_path: Two persistent credential records.
        scoped: Use separated cookies or the old shared cookie name.
    """
    _factory = ModuleFactory()
    local_auth = tmp_path / "web_auth.json"
    remote_auth = tmp_path / "remote-auth.json"
    remote_auth.write_text(json.dumps({"hash": "cd" * 32}))
    jar = CookieJar()
    for port, auth_path in [(55000, local_auth), (55001, remote_auth)]:
        web_auth.get_web_auth_path.return_value = str(auth_path)
        name = web_auth.session_cookie_name() if scoped else web_auth.SESSION_COOKIE_NAME
        message = Message()
        message["Set-Cookie"] = f"{name}={web_auth.issue_token()}; Path=/; HttpOnly; SameSite=Strict; Max-Age={web_auth.SESSION_TTL_SECONDS}"
        jar.extract_cookies(SimpleNamespace(info=lambda: message), Request(f"http://localhost:{port}/login"))
    assert len(list(jar)) == (2 if scoped else 1)
    for port, auth_path in [(55000, local_auth), (55001, remote_auth)]:
        web_auth.get_web_auth_path.return_value = str(auth_path)
        request = Request(f"http://localhost:{port}/api/identity")
        jar.add_cookie_header(request)
        cookies = SimpleCookie(request.get_header("Cookie"))
        assert web_auth.validate_session_cookies(
            {name: value.value for name, value in cookies.items()}
        ) is (scoped or port == 55001)


def test_invalid_credential_file_denies_cookie_authentication(tmp_path: Path) -> None:
    """Reject unreadable credentials rather than treating a request as logged in.

    Parameters:
        tmp_path: Isolated credential record to corrupt.
    """
    _factory = ModuleFactory()
    name = web_auth.session_cookie_name()
    token = web_auth.issue_token()
    (tmp_path / "web_auth.json").write_text("not-json")
    assert not web_auth.validate_session_cookies({name: token})


def test_is_locked_out_false_for_unknown_ip():
    assert not web_auth.is_locked_out("1.2.3.4")


def test_record_failed_login_locks_out_after_five_failures():
    ip = "1.2.3.4"
    for _ in range(4):
        web_auth.record_failed_login(ip)
    assert not web_auth.is_locked_out(ip)

    web_auth.record_failed_login(ip)

    assert web_auth.is_locked_out(ip)


def test_record_successful_login_clears_failed_attempts():
    ip = "1.2.3.4"
    for _ in range(5):
        web_auth.record_failed_login(ip)
    assert web_auth.is_locked_out(ip)

    web_auth.record_successful_login(ip)

    assert ip not in web_auth._login_attempts
    assert not web_auth.is_locked_out(ip)


def test_record_failed_login_evicts_oldest_entry_when_table_is_full(
    monkeypatch,
):
    monkeypatch.setattr(web_auth, "_MAX_TRACKED_IPS", 1)
    web_auth.record_failed_login("1.1.1.1")

    web_auth.record_failed_login("2.2.2.2")

    assert len(web_auth._login_attempts) == 1
    assert "2.2.2.2" in web_auth._login_attempts


def test_login_page_html_includes_error_message():
    html = web_auth.login_page_html("bad password")

    assert "bad password" in html
    assert 'action="/login"' in html


def test_login_page_html_without_error_omits_error_paragraph():
    html = web_auth.login_page_html(None, post_path="/api/login")

    assert '<p style="color:#c0392b">' not in html
    assert 'action="/api/login"' in html
