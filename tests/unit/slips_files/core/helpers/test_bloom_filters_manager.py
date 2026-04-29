# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock, patch

from tests.module_factory import ModuleFactory
from slips_files.core.helpers.bloom_filters_manager import BFManager


@patch("slips_files.core.helpers.bloom_filters_manager.DBManager")
@patch("slips_files.core.helpers.bloom_filters_manager.utils.supported_orgs", ["google"])
def test_init_whitelisted_orgs_bf_scales_first_octet_capacity(mock_db_manager):
    module_factory = ModuleFactory()
    manager = BFManager(
        logger=module_factory.logger,
        output_dir="output/",
        redis_port=6379,
        conf=Mock(),
        ppid=12345,
    )

    first_octets = {
        str(idx): [f"{idx}.0.0.0/8"] for idx in range(150)
    }
    manager.db.get_org_info.return_value = []
    manager.db.get_org_ips.return_value = first_octets

    manager._init_whitelisted_orgs_bf()

    assert "149" in manager.org_filters["google"]["first_octets"]
