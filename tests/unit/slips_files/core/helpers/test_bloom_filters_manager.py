# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

from slips_files.core.helpers.bloom_filters_manager import BFManager
from tests.module_factory import ModuleFactory


def test_serialization_reconnects_without_flushing() -> None:
    """Transfer bloom data while reopening the database in the receiving child."""
    factory = ModuleFactory()
    with patch(
        "slips_files.core.helpers.bloom_filters_manager.DBManager"
    ) as database_class:
        manager = BFManager(factory.logger, "output", 6385, Mock(), 123)
        manager.org_filters = {"example": {"domains": {"example.org"}}}
        state = manager.__getstate__()
        assert "db" not in state
        database_class.reset_mock()
        restored = BFManager.__new__(BFManager)
        restored.__setstate__(state)

        assert restored.org_filters == manager.org_filters
        database_class.assert_called_once_with(
            manager.logger,
            "output",
            6385,
            manager.conf,
            123,
            start_redis_server=False,
            flush_db=False,
        )


def test_init_whitelisted_orgs_bf_handles_large_org_subnet_lists():
    bf_manager = BFManager.__new__(BFManager)
    bf_manager.org_filters = {}
    bf_manager.db = Mock()

    domains = ["example.com", "example.org"]
    asns = ["AS64500", "AS64501"]
    org_ips = {f"10.{idx}.0.0/16": "test" for idx in range(250)}

    bf_manager.db.get_org_info.side_effect = lambda org, info_type: {
        "domains": domains,
        "asn": asns,
    }[info_type]
    bf_manager.db.get_org_ips.return_value = org_ips

    with patch(
        "slips_files.core.helpers.bloom_filters_manager.utils.supported_orgs",
        ["testorg"],
    ):
        bf_manager._init_whitelisted_orgs_bf()

    assert "testorg" in bf_manager.org_filters
    assert "example.com" in bf_manager.org_filters["testorg"]["domains"]
    assert "AS64500" in bf_manager.org_filters["testorg"]["asns"]
    assert "10.249.0.0/16" in bf_manager.org_filters["testorg"]["first_octets"]
