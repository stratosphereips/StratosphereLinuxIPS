from tests.module_factory import ModuleFactory
from slips_files.core.flows.zeek import Conn
import pytest

def test_is_supported_flow_not_ts(mock_rdb):
    flow = Conn(
        '1601998398.945854',
        '1234',
        '192.168.1.1',
        '8.8.8.8',
        5,
        'TCP',
        'dhcp',
        80,88,
        20,20,
        20,20,
        '','',
        'Established',''
    )
    flow.starttime = None
    flow_handler = ModuleFactory().create_flow_handler_obj(flow, mock_rdb)
    assert flow_handler.is_supported_flow() == False


@pytest.mark.parametrize(
    'flow_type, expected_val',
    [
        ('dhcp',True),
        ('oscp', False),
        ('notice',True),
     ]
)
def test_is_supported_flow_not_ts(
        flow_type: str, expected_val: bool, mock_rdb):
    flow = Conn(
        '1601998398.945854',
        '1234',
        '192.168.1.1',
        '8.8.8.8',
        5,
        'TCP',
        'dhcp',
        80,88,
        20,20,
        20,20,
        '','',
        'Established',''
    )
    flow.type_ = flow_type
    flow_handler = ModuleFactory().create_flow_handler_obj(flow, mock_rdb)
    assert flow_handler.is_supported_flow() == expected_val