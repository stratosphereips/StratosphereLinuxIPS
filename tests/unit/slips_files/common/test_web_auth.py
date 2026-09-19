# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the shared web interface session/login helpers."""
import time

import pytest

from slips_files.common import web_auth


@pytest.fixture(autouse=True)
def clear_login_attempts():
    """Each test gets a clean login-attempts table."""
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
        web_auth._SESSION_KEY, str(expiry).encode(), web_auth.sha256
    ).hexdigest()
    expired_token = f"{expiry}.{mac}"

    assert not web_auth.validate_token(expired_token)


def test_validate_token_rejects_tampered_signature():
    token = web_auth.issue_token()
    expiry_str, _, _ = token.partition(".")

    assert not web_auth.validate_token(f"{expiry_str}.deadbeef")


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
