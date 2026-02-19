# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/virustotal/virustotal.py"""

#### NOTE: this file should conjtain as minimum tests as possible due to the 4reqs/minute vt api quota
#####       if more than 4 calls to _api_query in a row winn cause unit tests to fail

from tests.module_factory import ModuleFactory
import pytest
import requests
import json


def get_vt_key():
    # get the user's api key
    try:
        with open("config/vt_api_key", "r") as f:
            api_key = f.read()
    except FileNotFoundError:
        api_key = ""

    return api_key


def have_available_quota(api_key):
    """
    Check if the used has available VT quota
    """

    def get_allowed(quota):
        return res.get(quota, {}).get("user", {}).get("allowed", 0)

    url = f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas"
    headers = {"Accept": "application/json", "x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            res = json.loads(response.text)["data"]
            api_requests_daily = get_allowed("api_requests_daily")
            api_requests_hourly = get_allowed("api_requests_hourly")
            api_requests_monthly = get_allowed("api_requests_monthly")
            quotas = (
                api_requests_daily,
                api_requests_hourly,
                api_requests_monthly,
            )
            quotas = list(map(int, quotas))

            return True if any(quotas) else "Not enough quota."
        else:
            error = json.loads(response.text)["error"]
            code = error["code"]
            msg = error["message"]
            return f"{response.status_code}: {code}, {msg}"
    except (
        requests.exceptions.ReadTimeout,
        requests.exceptions.ConnectionError,
        json.decoder.JSONDecodeError,
    ):
        return False


# only run the following tests if an API key was found
API_KEY = get_vt_key()
enough_quota = have_available_quota(API_KEY)
error_msg = "API key not found"
if enough_quota is not True:
    error_msg = f"server response {enough_quota}"

valid_api_key = pytest.mark.skipif(
    len(API_KEY) != 64 or enough_quota is not True,
    reason=f"API KEY not found or you do not have quota. error: {error_msg}",
)


# @pytest.mark.parametrize('ip', ['8.8.8.8'])
# def test_api_query_(output_queue, ip):
#     """
#     This one depends on the available quota
#     """
#     virustotal = create_virustotal_instance(output_queue, database)
#     response = virustotal.api_query_(ip)
#     # make sure response.status != 204 or 403
#     assert response != {}, 'Server Error: Response code is not 200'
#     assert response['response_code'] == 1


@pytest.mark.dependency(name="sufficient_quota")
@pytest.mark.parametrize("ip", ["8.8.8.8"])
@valid_api_key
def test_interpret_rsponse(ip):
    virustotal = ModuleFactory().create_virustotal_obj()
    response = virustotal.api_query_(ip)
    for ratio in virustotal.interpret_response(response):
        assert isinstance(ratio, float)


@pytest.mark.dependency(depends=["sufficient_quota"])
@valid_api_key
def test_get_domain_vt_data():
    virustotal = ModuleFactory().create_virustotal_obj()
    assert virustotal.get_domain_vt_data("google.com") is not False
