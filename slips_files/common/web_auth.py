# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Minimal session/login support shared by
(webinterface/app.py's Flask app, and modules/web_interface/server.py's
raw BaseHTTPRequestHandler). Gates access behind the same password used
for redis (see redis_auth.py) - one secret for a single local analyst to
remember.

This is deliberately not a full user-accounts system: slips is a
single-user, per-analysis tool, so one shared password behind a signed,
time-limited session cookie is the right amount of protection.
"""
import hmac
import secrets
import time
from hashlib import sha256
from typing import Dict, Optional, Tuple

SESSION_COOKIE_NAME = "slips_session"
SESSION_TTL_SECONDS = 8 * 60 * 60

# generated once per process. sessions are naturally invalidated whenever
# slips restarts, which matches a per-analysis tool.
_SESSION_KEY = secrets.token_bytes(32)

# ip -> (consecutive failed attempts, unlock-at epoch)
_login_attempts: Dict[str, Tuple[int, float]] = {}
_MAX_TRACKED_IPS = 1000


def issue_token() -> str:
    """returns a new signed, time-limited session token"""
    expiry = int(time.time()) + SESSION_TTL_SECONDS
    mac = hmac.new(_SESSION_KEY, str(expiry).encode(), sha256).hexdigest()
    return f"{expiry}.{mac}"


def validate_token(token: Optional[str]) -> bool:
    """checks a session token's signature and expiry"""
    if not token or "." not in token:
        return False
    expiry_str, _, mac = token.partition(".")
    try:
        expiry = int(expiry_str)
    except ValueError:
        return False
    if time.time() > expiry:
        return False
    expected = hmac.new(_SESSION_KEY, expiry_str.encode(), sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def is_locked_out(client_ip: str) -> bool:
    """True if this ip has failed enough logins recently to be throttled"""
    attempts, unlock_at = _login_attempts.get(client_ip, (0, 0.0))
    return time.time() < unlock_at


def record_failed_login(client_ip: str) -> None:
    """
    exponential backoff after repeated failures: 5th+ failure locks the ip
    out for (failures - 4) * 2 seconds.
    """
    if len(_login_attempts) >= _MAX_TRACKED_IPS:
        # evict an arbitrary (oldest-inserted) entry to bound memory use
        _login_attempts.pop(next(iter(_login_attempts)), None)

    attempts, _ = _login_attempts.get(client_ip, (0, 0.0))
    attempts += 1
    unlock_at = 0.0
    if attempts >= 5:
        unlock_at = time.time() + (attempts - 4) * 2
    _login_attempts[client_ip] = (attempts, unlock_at)


def record_successful_login(client_ip: str) -> None:
    _login_attempts.pop(client_ip, None)


def login_page_html(error: Optional[str], post_path: str = "/login") -> str:
    """one minimal, self-contained login form shared by both dashboards"""
    error_html = f'<p style="color:#c0392b">{error}</p>' if error else ""
    return f"""<!doctype html>
<html><head><title>Slips - login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ font-family: sans-serif; display:flex; justify-content:center;
        align-items:center; height:100vh; margin:0; background:#1b1f23; }}
form {{ background:#fff; padding:2rem; border-radius:8px; min-width:280px; }}
input {{ width:100%; padding:.5rem; margin:.5rem 0; box-sizing:border-box; }}
button {{ width:100%; padding:.5rem; }}
</style></head>
<body>
<form method="post" action="{post_path}">
<h2>Slips</h2>
{error_html}
<input type="password" name="password" placeholder="Redis / web password"
 autofocus required>
<button type="submit">Log in</button>
</form>
</body></html>"""
