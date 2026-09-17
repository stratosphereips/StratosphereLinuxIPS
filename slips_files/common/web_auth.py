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
import os
import pwd
import secrets
import time
from hashlib import sha256
from html import escape
from typing import Dict, Optional, Tuple

from slips_files.core.database.redis_db.redis_auth import (
    get_redis_auth_conf_path,
)

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
<img class="login-logo" src="/slips-logo.png" alt="Slips">
<h2>Slips</h2>
<p class="password-hint">{escape(_password_hint())}</p>
</div>
{error_html}
<input type="password" name="password" placeholder="Redis Database Password"
 autofocus required>
<button type="submit">Log in</button>
</form>
</body></html>"""
