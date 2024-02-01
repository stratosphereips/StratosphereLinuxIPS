from tests.module_factory import ModuleFactory
import pytest


def test_is_supported_flow_not_ts(flow,
                                  mock_db
                                  ):
    flow.starttime = None
    flow_handler = ModuleFactory().create_flow_handler_obj(flow, mock_db)
    assert flow_handler.is_supported_flow() == False


@pytest.mark.parametrize(
    'flow_type, expected_val',
    [
        ('dhcp',True),
        ('oscp', False),
        ('notice',True),
     ]
)
def test_is_supported_flow_without_ts(
        flow_type: str, expected_val: bool, flow,
        mock_db
        ):
    # just change the flow_type
    flow.type_ = flow_type
    flow_handler = ModuleFactory().create_flow_handler_obj(flow, mock_db)
    assert flow_handler.is_supported_flow() == expected_val

