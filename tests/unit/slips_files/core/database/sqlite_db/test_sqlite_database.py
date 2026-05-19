# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.flows.zeek import (
    Conn,
    HTTP,
)


@pytest.fixture
def db(tmp_path):
    logger = MagicMock()
    return SQLiteDB(logger, str(tmp_path), 12345)


def test_sqlite_lockfile_is_owner_only_writable(tmp_path):
    logger = MagicMock()
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    with patch(
        "slips_files.common.sqlite_flock.SLIPS_LOCKS_DIR", str(locks_dir)
    ):
        db = SQLiteDB(logger, str(tmp_path), 12345)

    assert locks_dir.exists()
    assert db.lockfile_path.endswith("sqlite_db.lock")
    assert oct(os.stat(db.lockfile_path).st_mode & 0o777) == "0o600"


def test_get_flow_uses_parameterized_query(db):
    flow = Conn(
        starttime="1.0",
        uid='uid" OR 1=1 --',
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12345",
        dport="80",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )

    db.add_flow(flow, "profile-a", "tw-1")

    result = db.get_flow(flow.uid)

    assert json.loads(result[flow.uid])["uid"] == flow.uid


def test_set_flow_label_and_altflow_lookup_handle_quoted_values(db):
    uid = 'uid" OR 1=1 --'
    altflow = HTTP(
        starttime="1.0",
        uid=uid,
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        method="GET",
        host='example"host.test',
        uri="/index.html",
        version=1,
        user_agent="pytest",
        request_body_len=0,
        response_body_len=0,
        status_code="200",
        status_msg="OK",
        resp_mime_types="text/html",
        resp_fuids="",
        interface="eth0",
    )

    db.add_altflow(altflow, "profile-a", "tw-1")
    db.set_flow_label([uid], 'malicious"label')

    fetched_altflow = db.get_altflow_from_uid(uid)
    stored_label = db.select(
        "altflows",
        columns="label",
        condition="uid = ?",
        params=(uid,),
        limit=1,
    )

    assert fetched_altflow["uid"] == uid
    assert stored_label[0] == 'malicious"label'


def test_get_flows_count_handles_quoted_filters(db):
    first_flow = Conn(
        starttime="1.0",
        uid="flow-1",
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12345",
        dport="80",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )
    second_flow = Conn(
        starttime="2.0",
        uid="flow-2",
        saddr="192.168.1.11",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12346",
        dport="443",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )

    db.add_flow(first_flow, 'profile"quoted', 'tw"quoted')
    db.add_flow(second_flow, 'profile"quoted', "tw-other")

    assert db.get_flows_count(profileid='profile"quoted') == 2
    assert (
        db.get_flows_count(profileid='profile"quoted', twid='tw"quoted') == 1
    )


def test_get_columns_rejects_unknown_tables(db):
    with pytest.raises(ValueError, match="Invalid SQLiteDB table name"):
        db.get_columns("flows; DROP TABLE flows;")
