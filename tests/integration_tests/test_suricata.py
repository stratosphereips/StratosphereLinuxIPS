"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""
from tests.common_test_utils import (
        get_total_profiles,
        is_evidence_present,
        create_output_dir,
        has_errors,
        alerts_file,
        run_slips,
)
from tests.module_factory import ModuleFactory
import pytest
from ...slips import *
import shutil


@pytest.mark.parametrize(
    'suricata_path,  output_dir, redis_port, expected_evidence',
    [
        (
                'dataset/test6-malicious.suricata.json',
                'test6/',
                6657,
                [
                    'Connection to unknown destination port',
                    'vertical port scan',
                    'Connecting to private IP',
                    'non-HTTP established connection'

                ]

        )
    ],
)
def test_suricata(
        suricata_path,
        output_dir,
        redis_port,
        expected_evidence
        ):
    output_dir = create_output_dir(output_dir)
    # we have an established flow in suricata file to this port 8760/udp
    # {"timestamp":"2021-06-06T15:57:37.272281+0200","flow_id":1630350322382106,"event_type":"flow",
    # "src_ip":"192.168.1.129","src_port":36101,"dest_ip":"122.248.252.67","dest_port":8760,"proto":
    # "UDP","app_proto":"failed","flow":{"pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":256,
    # "bytes_toclient":468,"start":"2021-06-07T04:26:27.668954+0200","end":"2021-06-07T04:26:27.838624+0200"
    # ,"age":0,"state":"established","reason":"shutdown","alerted":false},"host":"stratosphere.org"}

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {suricata_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    # todo the profiles should be way more than 10, maybe 76, but it varies each run, we need to sy why
    assert profiles > 10

    log_file = os.path.join(output_dir, alerts_file)
    assert any(is_evidence_present(log_file, ev) for ev in expected_evidence)
    shutil.rmtree(output_dir)



