# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Minimal session/login support shared by
(webinterface/app.py's Flask app, and modules/web_interface/server.py's
raw BaseHTTPRequestHandler). Gates access behind the same password used
for redis (see redis_auth.py) - one secret for a single local analyst to
remember.

This is deliberately not a full user-accounts system: Slips is a
single-user tool, so one shared password behind a signed, persistent
session cookie is the right amount of protection.
"""
from collections.abc import Mapping
import hmac
import json
import os
import pwd
import time
from hashlib import sha256
from html import escape
from typing import Dict, Optional, Tuple

from slips_files.core.database.redis_db.redis_auth import (
    ensure_web_password_matches_redis_password,
    get_redis_auth_conf_path,
    get_web_auth_path,
)

SESSION_COOKIE_NAME = "slips_session"
SESSION_TTL_SECONDS = 365 * 24 * 60 * 60

# ip -> (consecutive failed attempts, unlock-at epoch)
_login_attempts: Dict[str, Tuple[int, float]] = {}
_MAX_TRACKED_IPS = 1000


def _session_signing_key() -> bytes:
    """Derive a stable session key from the persistent web password hash.

    Returns:
        Key shared by web server processes until the web password changes.
    """
    ensure_web_password_matches_redis_password()
    with open(get_web_auth_path(), "r") as auth_file:
        password_hash = bytes.fromhex(json.load(auth_file)["hash"])
    if len(password_hash) != 32:
        raise ValueError("Invalid web password hash")
    return sha256(b"Slips web session v2\0" + password_hash).digest()


def issue_token() -> str:
    """returns a new signed, time-limited session token"""
    expiry = int(time.time()) + SESSION_TTL_SECONDS
    mac = hmac.new(
        _session_signing_key(), str(expiry).encode(), sha256
    ).hexdigest()
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
    try:
        key = _session_signing_key()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return False
    expected = hmac.new(key, expiry_str.encode(), sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def session_cookie_name() -> str:
    """Keep independent Slips logins separate on a shared browser hostname.

    Returns:
        Stable cookie name for these persistent web credentials.
    """
    identity = sha256(_session_signing_key()).hexdigest()[:16]
    return f"{SESSION_COOKIE_NAME}_{identity}"


def validate_session_cookies(values: Mapping[str, str]) -> bool:
    """Validate this installation's cookie, accepting older sessions on upgrade.

    Parameters:
        values: Cookie names and values supplied by the browser.

    Returns:
        Whether this installation's session is valid. A present scoped cookie
        takes priority over the legacy shared name.
    """
    try:
        name = session_cookie_name()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return False
    if name in values:
        return validate_token(values[name])
    return validate_token(values.get(SESSION_COOKIE_NAME))


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


def _password_hint() -> str:
    """
    text shown on the login page pointing the analyst at the file
    holding the shared redis/web password, and who on the host owns it.
    """
    path = get_redis_auth_conf_path()
    try:
        owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (OSError, KeyError):
        owner = "the user who started Slips"
    return f"check {path} for {owner}'s password."


def login_page_html(error: Optional[str], post_path: str = "/login") -> str:
    """one minimal, self-contained login form shared by both dashboards"""
    error_html = f'<p style="color:var(--danger)">{error}</p>' if error else ""
    return f"""<!doctype html>
<html><head><title>Slips - login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/slips-logo.png?v=4" type="image/png" sizes="512x512">
<style>
:root {{
  color-scheme: dark;
  --bg: #091017;
  --surface: #101a23;
  --line: #263a49;
  --text: #e6edf3;
  --muted: #8da2b2;
  --accent: #43c7b5;
  --danger: #ef6b73;
}}
* {{ box-sizing: border-box; }}
body {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif; display:flex;
        justify-content:center; align-items:center; height:100vh; margin:0;
        background:var(--bg); color:var(--text); }}
form {{ background:var(--surface); border:1px solid var(--line);
        padding:2rem; border-radius:10px; min-width:280px; }}
.login-brand {{ display:flex; flex-direction:column; align-items:center;
        gap:.6rem; margin-bottom:1.3rem; }}
.login-logo {{ width:64px; height:64px; object-fit:contain; }}
h2 {{ margin:0; font-size:.95rem; font-weight:850; letter-spacing:.14em;
      text-transform:uppercase; text-align:center; }}
.password-hint {{ margin-top:.35rem; color:var(--muted); font-size:.72rem;
      text-align:center; overflow-wrap:anywhere; }}
input {{ width:100%; padding:.6rem; margin:.5rem 0; box-sizing:border-box;
         border:1px solid var(--line); border-radius:7px;
         background:var(--bg); color:var(--text); }}
input::placeholder {{ color:var(--muted); }}
button {{ width:100%; padding:.6rem; margin-top:.4rem; border:1px solid var(--accent);
          border-radius:7px; background:var(--accent); color:#04211c;
          font-weight:650; cursor:pointer; }}
button:hover {{ opacity:.9; }}
</style></head>
<body>
<form method="post" action="{post_path}">
<div class="login-brand">
<img class="login-logo" src="/slips-logo.png?v=4" alt="Slips">
<h2>Slips</h2>
<p class="password-hint">{escape(_password_hint())}</p>
</div>
{error_html}
<input type="password" name="password" placeholder="Redis Database Password"
 autofocus required>
<button type="submit">Log in</button>
</form>
</body></html>"""
