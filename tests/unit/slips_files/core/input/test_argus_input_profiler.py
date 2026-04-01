# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock

from slips_files.core.input_profilers.argus import Argus


def test_argus_parser_skips_repeated_headers_and_parses_short_binetflow():
    parser = Argus(Mock())
    header = {
        "data": (
            "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,"
            "State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label"
        )
    }
    flow_line = {
        "data": (
            "2018/09/27 22:40:52.362768,193.831726,tcp,192.168.2.1,52893,"
            "  <?>,192.168.2.12,22,CON,16,16,35,3766,1224,"
        )
    }

    flow, err = parser.process_line(header)
    assert flow is False
    assert err == "Defined Columns"

    flow, err = parser.process_line(header)
    assert flow is False
    assert err == "Defined Columns"

    flow, err = parser.process_line(flow_line)
    assert err == ""
    assert flow.pkts == 35
    assert flow.bytes == 3766
    assert flow.sbytes == 1224
    assert flow.dbytes == 0
    assert flow.spkts == 0
    assert flow.dpkts == 0
