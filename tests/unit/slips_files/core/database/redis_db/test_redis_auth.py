# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Tests for redis password generation/storage and the anti-leak invariant."""
import shlex
import stat
from unittest.mock import MagicMock

import pytest
import redis

from slips_files.core.database.redis_db import redis_auth


@pytest.fixture(autouse=True)
def isolate_permanent_dir(tmp_path, monkeypatch):
    """Point the module at a throwaway permanent/ dir and clear its cache."""
    monkeypatch.setattr(
        redis_auth,
        "get_this_filepath_inside_permanent_dir",
        lambda filename: str(tmp_path / filename),
    )
    monkeypatch.setattr(redis_auth, "_cached_password", None)
    yield
    monkeypatch.setattr(redis_auth, "_cached_password", None)


def test_ensure_redis_password_creates_a_600_file(tmp_path):
    password = redis_auth.ensure_redis_password()

    conf_path = tmp_path / redis_auth.REDIS_AUTH_CONF_FILENAME
    assert conf_path.exists()
    mode = stat.S_IMODE(conf_path.stat().st_mode)
    assert mode == 0o600
    assert conf_path.read_text() == f"requirepass {password}\n"


def test_ensure_redis_password_is_reused_across_calls(tmp_path):
    first = redis_auth.ensure_redis_password()
    redis_auth._cached_password = None  # force a re-read from disk
    second = redis_auth.ensure_redis_password()

    assert first == second


def test_ensure_redis_password_survives_creation_race(tmp_path):
    """
    if the file already exists when we try to create it (another slips
    process won the race), we must read its password, not crash or
    overwrite it with a different one.
    """
    conf_path = tmp_path / redis_auth.REDIS_AUTH_CONF_FILENAME
    conf_path.write_text("requirepass someone-elses-password\n")
    import os

    os.chmod(conf_path, 0o600)

    assert redis_auth.ensure_redis_password() == "someone-elses-password"


def test_redis_auth_kwargs_only_exposes_password():
    kwargs = redis_auth.redis_auth_kwargs()
    assert set(kwargs) == {"password"}
    assert kwargs["password"] == redis_auth.ensure_redis_password()


def test_web_password_hash_roundtrip():
    redis_auth.set_web_password("correct horse battery staple")

    assert redis_auth.verify_web_password("correct horse battery staple")
    assert not redis_auth.verify_web_password("wrong password")


def test_try_connect_with_and_without_password_falls_back_on_legacy_server():
    """
    an old, not-yet-upgraded redis-server that never got a requirepass
    responds to AUTH with "no password is set" - we must retry without a
    password instead of failing the whole connection.
    """
    authenticated_client = MagicMock()
    authenticated_client.ping.side_effect = redis.exceptions.ResponseError(
        "ERR Client sent AUTH, but no password is set"
    )
    unauthenticated_client = MagicMock()

    connect = MagicMock(
        side_effect=[authenticated_client, unauthenticated_client]
    )

    result = redis_auth.try_connect_with_and_without_password(
        connect, host="127.0.0.1", port=6379
    )

    assert result is unauthenticated_client
    assert connect.call_count == 2
    _, first_kwargs = connect.call_args_list[0]
    assert "password" in first_kwargs
    _, second_kwargs = connect.call_args_list[1]
    assert "password" not in second_kwargs


def test_try_connect_with_and_without_password_reraises_other_errors():
    client = MagicMock()
    client.ping.side_effect = redis.exceptions.ResponseError(
        "WRONGPASS invalid username-password pair"
    )
    connect = MagicMock(return_value=client)

    with pytest.raises(redis.exceptions.ResponseError):
        redis_auth.try_connect_with_and_without_password(
            connect, host="127.0.0.1", port=6379
        )


def test_redis_server_command_never_contains_the_password(monkeypatch):
    """
    the password must only ever reach redis-server through the `include`d
    conf file - never through argv, since the argv is both logged
    (shlex.join(cmd)) and visible to every local user via `ps aux`.
    """
    password = redis_auth.ensure_redis_password()

    cmd = [
        "redis-server",
        "/some/output/dir/redis/redis-server-port-32768.conf",
        "--port",
        "32768",
        "--bind",
        "127.0.0.1",
        "--daemonize",
        "yes",
    ]

    assert password not in shlex.join(cmd)
    assert password not in " ".join(cmd)
