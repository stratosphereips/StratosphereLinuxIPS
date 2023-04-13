import pytest
import redis
import json

'''
This test suite tests the correct types / data in redis database. 
The data from the database is displayed in the webinterface, so
if the data type was changed, it should be changed accordingly in webinterface.

The test are run on specific data - 
'''
TYPE_SET = 'set'
TYPE_ZSET = 'zset'
TYPE_HASH = 'hash'

__database__ = redis.StrictRedis(host='localhost',
                                 port=6379,
                                 db=0,
                                 charset="utf-8",
                                 socket_keepalive=True,
                                 retry_on_timeout=True,
                                 decode_responses=True,
                                 health_check_interval=30)


__cache__ = redis.StrictRedis(host='localhost',
                                                port=6379,
                                                db=1,
                                                charset="utf-8",
                                                socket_keepalive=True,
                                                retry_on_timeout=True,
                                                decode_responses=True,
                                                health_check_interval=30)

"""
Helper functions for testing
"""
def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError:
    return False
  return True


"""
Test functions
"""
def test_type_profiles_correct():
  test_key = "profiles"
  assert __database__.type(test_key) == TYPE_SET
  assert 'profile_' in list(__database__.smembers(test_key))[0]


def test_type_tws_correct():
  test_key = "twsprofile_188.110.58.51"
  assert __database__.type(test_key) == TYPE_ZSET
  assert 'timewindow' in __database__.zrange(test_key, 0, -1)[0]


def test_type_outtuples_correct():
  test_key = "profile_188.110.58.51_timewindow1"
  test_field = "OutTuples"
  assert __database__.type(test_key) == TYPE_HASH

  outtuples = __database__.hget(test_key, test_field)
  assert is_json(outtuples) is True

  outtuples = json.loads(outtuples)
  assert type(outtuples) is dict

  first_keypair = list(outtuples.items())[0]
  assert type(first_keypair[1]) is list


def test_type_IPsInfo_correct():
  test_key = "IPsInfo"
  test_field = "188.110.58.51"

  assert __cache__.type(test_key) == TYPE_HASH
  ip_info = __cache__.hget(test_key, test_field)
  assert is_json(ip_info) is True

  ip_info = json.loads(ip_info)
  assert type(ip_info) is dict


def test_type_timeline_correct():
  test_key = "profile_188.110.58.51_timewindow1_timeline"
  table_fields = ["timestamp", "dport_name", "preposition", "daddr"]
  assert __database__.type(test_key) == TYPE_ZSET

  timeline = __database__.zrange(test_key, 0,-1)
  for id in range(len(timeline)):
    line = timeline[id]
    assert is_json(line)
    line = json.loads(line)
    for field in table_fields:
      assert field in line


def test_type_flows_correct():
  test_key = "profile_188.110.58.51_timewindow1_flows"
  table_fields = ["ts", "dur", "saddr", "sport", "daddr", "dport", "proto", "origstate","state", "pkts", "allbytes", "spkts", "sbytes"]

  assert __database__.type(test_key) == TYPE_HASH
  flows = __database__.hgetall(test_key)

  for key, value in flows.items():
    line = flows[key]
    assert is_json(line)
    line = json.loads(line)
    for field in table_fields:
      assert field in line


if __name__ == "__main__":
    pytest.main()

