"""Unit test for modules/http_analyzer/http_analyzer.py"""
from tests.module_factory import ModuleFactory
import random

# dummy params used for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
uid = 'CAeDWs37BipkfP21u8'
timestamp = 1635765895.037696
SAFARI_UA = (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) '
        'AppleWebKit/605.1.15 (KHTML, like Gecko) '
        'Version/15.3 Safari/605.1.15'
    )

def get_random_MAC():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))



def test_check_suspicious_user_agents(mock_rdb):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # create a flow with suspicious user agent
    host = '147.32.80.7'
    uri = '/wpad.dat'
    user_agent = 'CHM_MSDN'
    assert (
        http_analyzer.check_suspicious_user_agents(uid, host, uri, timestamp, user_agent, profileid, twid) is True
    )


def test_check_multiple_google_connections(mock_rdb):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # {"ts":1635765765.435485,"uid":"C7mv0u4M1zqJBHydgj",
    # "id.orig_h":"192.168.1.28","id.orig_p":52102,"id.resp_h":"216.58.198.78",
    # "id.resp_p":80,"trans_depth":1,"method":"GET","host":"google.com","uri":"/",
    # "version":"1.1","user_agent":"Wget/1.20.3 (linux-gnu)","request_body_len":0,"response_body_len":219,
    # "status_code":301,"status_msg":"Moved Permanently","tags":[],"resp_fuids":["FGhwTU1OdvlfLrzBKc"],
    # "resp_mime_types":["text/html"]}
    host = 'google.com'
    # uri = '/'
    request_body_len = 0
    for _ in range(4):
        found_detection = http_analyzer.check_multiple_empty_connections(
            uid, host, timestamp, request_body_len, profileid, twid
        )
    assert found_detection is True

def test_parsing_online_ua_info(mock_rdb, mocker):
    """
    tests the parsing and processing the ua found by the online query
    """
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # use a different profile for this unit test to make sure we don't already have info about
    # it in the db
    profileid = 'profile_192.168.99.99'

    mock_rdb.get_user_agent_from_profile.return_value = None
    # mock the function that gets info about the given ua from an online db
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = """{
        "agent_name":"Safari",
        "os_type":"Macintosh",
        "os_name":"OS X"
    }"""

    # add os_type , os_name and agent_name to the db
    ua_info = http_analyzer.get_user_agent_info(SAFARI_UA, profileid)
    assert ua_info['os_type'] == 'Macintosh'
    assert ua_info['browser'] == 'Safari'


def test_get_user_agent_info(mock_rdb, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # mock the function that gets info about the
    # given ua from an online db: get_ua_info_online()
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = """{
        "agent_name":"Safari",
        "os_type":"Macintosh",
        "os_name":"OS X"
    }"""

    mock_rdb.add_all_user_agent_to_profile.return_value = True
    mock_rdb.get_user_agent_from_profile.return_value = None

    expected_ret_value = {'browser': 'Safari',
                          'os_name': 'OS X',
                          'os_type': 'Macintosh',
                          'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15'}
    assert http_analyzer.get_user_agent_info(SAFARI_UA, profileid) == expected_ret_value
    # # get ua info online, and add os_type , os_name and agent_name anout this profile
    # # to the db
    # assert ua_added_to_db is not None, 'Error getting UA info online'
    # assert ua_added_to_db is not False, 'We already have UA info about this profile in the db'

def test_check_incompatible_user_agent(mock_rdb):

    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # use a different profile for this unit test to make sure we don't already have info about
    # it in the db. it has to be a private IP for its' MAC to not be marked as the gw MAC
    profileid = 'profile_192.168.77.254'

    # Mimic an intel mac vendor using safari
    mock_rdb.get_mac_vendor_from_profile.return_value = 'Intel Corp'
    mock_rdb.get_user_agent_from_profile.return_value = {'browser': 'safari'}

    assert (
        http_analyzer.check_incompatible_user_agent('google.com', '/images', timestamp, profileid, twid, uid) is True
    )


def test_extract_info_from_UA(mock_rdb):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    # use another profile, because the default
    # one already has a ua in the db
    mock_rdb.get_user_agent_from_profile.return_value = None
    profileid = 'profile_192.168.1.2'
    server_bag_ua = 'server-bag[macOS,11.5.1,20G80,MacBookAir10,1]'
    assert (
        http_analyzer.extract_info_from_UA(server_bag_ua, profileid)
        == '{"user_agent": "macOS,11.5.1,20G80,MacBookAir10,1", "os_name": "macOS", "os_type": "macOS11.5.1", "browser": ""}'
    )


def test_check_multiple_UAs(mock_rdb):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_rdb)
    mozilla_ua = 'Mozilla/5.0 (X11; Fedora;Linux x86; rv:60.0) Gecko/20100101 Firefox/60.0'
    # old ua
    cached_ua = {'os_type': 'Fedora', 'os_name': 'Linux'}
    # current ua
    user_agent = mozilla_ua
    # should set evidence
    assert (
        http_analyzer.check_multiple_UAs(cached_ua, user_agent, timestamp, profileid, twid, uid) is False
    )
    # in this case we should alert
    user_agent = SAFARI_UA
    assert (
        http_analyzer.check_multiple_UAs(cached_ua, user_agent, timestamp, profileid, twid, uid) is True
    )
