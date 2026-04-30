# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

from slips_files.core.helpers.bloom_filters_manager import BFManager


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
