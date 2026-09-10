# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Generates, stores, and hands out the shared Redis password Slips uses to
authenticate to every redis-server instance it starts or connects to.

The password is persistent (not per-run) because slips keeps a long-lived
shared cache server on port 6379 (see RedisDB.rcache) that outlives any
single analysis run.
"""
import hashlib
import hmac
import json
import os
import secrets
from typing import Dict, Optional

import redis

from slips_files.common.output_paths import (
    get_this_filepath_inside_permanent_dir,
)

REDIS_AUTH_CONF_FILENAME = "redis_auth.conf"
WEB_AUTH_FILENAME = "web_auth.json"
REQUIREPASS_PREFIX = "requirepass "

_cached_password: Optional[str] = None


def get_redis_auth_conf_path() -> str:
    """
    absolute path to the persistent conf file that holds the
    `requirepass` directive slips includes in every redis-server conf.
    """
    return get_this_filepath_inside_permanent_dir(REDIS_AUTH_CONF_FILENAME)


def get_web_auth_path() -> str:
    """absolute path to the json file holding the web login password hash"""
    return get_this_filepath_inside_permanent_dir(WEB_AUTH_FILENAME)


def _read_password_from_conf(conf_path: str) -> Optional[str]:
    # deliberately uses os.open/os.fdopen instead of builtins.open: this
    # runs on every redis connection, including ones made while tests have
    # builtins.open patched out to keep other fixtures from touching disk.
    fd = os.open(conf_path, os.O_RDONLY)
    with os.fdopen(fd, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith(REQUIREPASS_PREFIX):
                return line[len(REQUIREPASS_PREFIX) :].strip()
    return None


def ensure_redis_password() -> str:
    """
    Returns the persistent redis password, generating and storing it
    (mode 0600) the first time it's needed. Safe to call concurrently from
    multiple slips processes: only one of them wins the creation race, the
    rest just read the file the winner created.
    """
    global _cached_password
    if _cached_password:
        return _cached_password

    conf_path = get_redis_auth_conf_path()

    if not os.path.exists(conf_path):
        password = secrets.token_urlsafe(32)
        try:
            fd = os.open(
                conf_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            with os.fdopen(fd, "w") as f:
                f.write(f"{REQUIREPASS_PREFIX}{password}\n")
            print(
                "Generated a new Redis password, stored at "
                f"{conf_path} (permissions 600). Keep this file safe: "
                "it's required to connect to redis and to log in to the "
                "web interface."
            )
        except FileExistsError:
            # another slips process won the creation race, fall through
            # to reading the file it created
            pass

    os.chmod(conf_path, 0o600)
    password = _read_password_from_conf(conf_path)
    if not password:
        raise RuntimeError(
            f"redis_auth: {conf_path} exists but has no requirepass line"
        )

    _cached_password = password
    return password


def redis_auth_kwargs() -> Dict[str, str]:
    """
    kwargs to splat into redis.StrictRedis(...)/redis.Redis(...) so every
    call site doesn't have to import/call ensure_redis_password() itself.
    """
    return {"password": ensure_redis_password()}


def try_connect_with_and_without_password(
    connect, *args, **kwargs
) -> redis.StrictRedis:
    """
    Calls connect(*args, password=<redis password>, **kwargs), and if the
    server responds that it isn't expecting a password (i.e. it's an old
    redis-server that was started before slips supported auth), retries
    once without a password.
    :param connect: a callable that builds a redis client, e.g.
        redis.StrictRedis
    """
    # different redis-server versions phrase this differently: pre-ACL
    # servers (<6) say "no password is set", ACL-based servers (>=6) say
    # "without any password configured".
    NO_PASSWORD_NEEDED_MARKERS = (
        "no password is set",
        "without any password configured",
    )

    client = connect(*args, password=ensure_redis_password(), **kwargs)
    try:
        client.ping()
        return client
    except (
        redis.exceptions.ResponseError,
        redis.exceptions.AuthenticationError,
    ) as e:
        error_text = str(e).lower()
        if not any(m in error_text for m in NO_PASSWORD_NEEDED_MARKERS):
            raise
        print(
            "Warning: connected to a Redis server started before "
            "authentication was added. Consider restarting it "
            "(./slips.py -k) so it picks up the new password."
        )
        return connect(*args, **kwargs)


def _scrypt_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32
    )


def set_web_password(password: str) -> None:
    """(re)generates the web-login hash file from a plaintext password"""
    salt = secrets.token_bytes(16)
    derived = _scrypt_hash(password, salt)
    web_auth_path = get_web_auth_path()
    fd = os.open(
        web_auth_path,
        os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
        0o600,
    )
    with os.fdopen(fd, "w") as f:
        json.dump(
            {
                "algo": "scrypt",
                "salt": salt.hex(),
                "hash": derived.hex(),
                "n": 16384,
                "r": 8,
                "p": 1,
            },
            f,
        )
    os.chmod(web_auth_path, 0o600)


def ensure_web_password_matches_redis_password() -> None:
    """
    By default the web login password is the same as the redis password:
    one secret to remember. Generates the web_auth.json hash the first
    time it's needed.
    """
    if not os.path.exists(get_web_auth_path()):
        set_web_password(ensure_redis_password())


def verify_web_password(candidate: str) -> bool:
    """constant-time check of a submitted password against the stored hash"""
    web_auth_path = get_web_auth_path()
    if not os.path.exists(web_auth_path):
        return False
    try:
        with open(web_auth_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False

    salt = bytes.fromhex(data["salt"])
    expected = bytes.fromhex(data["hash"])
    actual = hashlib.scrypt(
        candidate.encode(),
        salt=salt,
        n=data.get("n", 16384),
        r=data.get("r", 8),
        p=data.get("p", 1),
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


if __name__ == "__main__":
    # used by install/install.sh to generate the password ahead of starting
    # the shared cache redis-server on port 6379
    ensure_redis_password()
    ensure_web_password_matches_redis_password()
