import ipaddress
import redis
import os
import json

# random values for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
test_ip = '192.168.1.1'

def test_getProfileIdFromIP(database):
    """ unit test for addProfile and getProfileIdFromIP """
    # add a profile
    database.addProfile('profile_192.168.1.1','00:00','1')
    # try to retrieve it
    assert database.getProfileIdFromIP(test_ip) != False

def test_timewindows(database):
    """ unit tests for addNewTW ,getLastTWforProfile and getFirstTWforProfile """
    profileid = 'profile_192.168.1.1'
    # add a profile
    database.addProfile(profileid,'00:00','1')
    # add a tw to that profile (first tw)
    database.addNewTW(profileid, 0.0)
    # add  a new tw (last tw)
    database.addNewTW(profileid, 5.0)
    assert database.getFirstTWforProfile(profileid) == [('timewindow1', 0.0)]
    assert database.getLastTWforProfile(profileid) == [('timewindow2', 5.0)]

def getSlipsInternalTime():
    """ return a random time for testing"""
    return 50.0

def test_add_ips(database):
    # add a profile
    database.addProfile(profileid,'00:00','1')
    # add a tw to that profile
    database.addNewTW(profileid, 0.0)
    columns = {'dport':80,
              'sport':80,
              'totbytes':80,
              'pkts':20,
              'sbytes':30,
              'bytes':30,
              'spkts':70,
              'state':'notestablished',
              'uid' : '1234',
              'proto':'TCP',
              'saddr': '8.8.8.8',
              'daddr': test_ip,
              'starttime': '20.0'}
    # make sure ip is added
    assert database.add_ips(profileid, twid, ipaddress.ip_address(test_ip), columns, 'Server' ) == True
    hash_id = profileid + '_'+ twid
    stored_dstips = database.r.hget(hash_id,'SrcIPs')
    assert stored_dstips == '{"192.168.1.1": 1}'


def test_add_port(database):
    columns = {'dport':80,
              'sport':88,
              'totbytes':80,
              'pkts':20,
              'sbytes':30,
              'bytes':30,
              'spkts':70,
              'state':'notestablished',
              'proto':'TCP',
              'saddr': '8.8.8.8',
              'daddr': test_ip,
              'uid' : '1234',
              'starttime': '20.0'}
    database.add_port(profileid, twid, test_ip, columns, 'Server','Dst')
    hash_key = profileid + '_' + twid
    added_ports = database.r.hgetall(hash_key)
    assert 'SrcIPsServerTCPEstablished' in added_ports.keys()
    assert test_ip in added_ports['SrcIPsServerTCPEstablished']

def test_setEvidence(database):
    type_detection = 'ip'
    detection_info = test_ip
    type_evidence = f'SSHSuccessful-by-{detection_info}'
    threat_level = 0.01
    confidence = 0.6
    description = 'SSH Successful to IP :' + '8.8.8.8' + '. From IP ' + test_ip
    timestamp = ''
    category = 'Infomation'
    uid = '123'
    database.setEvidence(type_evidence, type_detection, detection_info, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)

    added_evidence = database.r.hget('evidence'+profileid, twid)
    added_evidence2 = database.r.hget(profileid + '_' + twid, 'Evidence')
    assert added_evidence2 == added_evidence

    added_evidence = json.loads(added_evidence)
    current_evidence_key = 'SSH Successful to IP :8.8.8.8. From IP 192.168.1.1'
    #  note that added_evidence may have evidence from other unit tests
    assert current_evidence_key in added_evidence.keys()

def test_deleteEvidence(database):
    description =  "SSH Successful to IP :8.8.8.8. From IP 192.168.1.1"
    database.deleteEvidence(profileid, twid, description)
    added_evidence = json.loads(database.r.hget('evidence'+profileid, twid))
    added_evidence2 = json.loads(database.r.hget(profileid + '_' + twid, 'Evidence'))
    assert 'SSHSuccessful-by-192.168.1.1' not in added_evidence
    assert 'SSHSuccessful-by-192.168.1.1' not in added_evidence2

def test_add_flow(database):
    starttime = '5'
    dur = '5'
    sport = 80
    dport = 88
    saddr_as_obj = ipaddress.ip_address(test_ip)
    daddr_as_obj = ipaddress.ip_address('8.8.8.8')
    proto = 'TCP'
    state = 'established'
    pkts = 20
    allbytes = 20
    spkts = 20
    sbytes = 20
    appproto = 'dhcp'
    uid = '1234'
    flow_type =  ""
    assert database.add_flow(profileid=profileid, twid=twid, stime=starttime, dur=dur,
                                          saddr=str(saddr_as_obj), sport=sport,
                                          daddr=str(daddr_as_obj),
                                          dport=dport, proto=proto,
                                          state=state, pkts=pkts, allbytes=allbytes,
                                          spkts=spkts, sbytes=sbytes,
                                          appproto=appproto, uid=uid,
                                          flow_type=flow_type) == True
    assert database.r.hget(profileid + '_' + twid + '_' + 'flows', uid) == '{"ts": "5", "dur": "5", "saddr": "192.168.1.1", "sport": 80, "daddr": "8.8.8.8", "dport": 88, "proto": "TCP", "origstate": "established", "state": "Established", "pkts": 20, "allbytes": 20, "spkts": 20, "sbytes": 20, "appproto": "dhcp", "label": "", "flow_type": "", "module_labels": {}}'


def test_module_labels(database):
    """ tests set and get_module_labels_from_flow """
    module_label = 'malicious'
    module_name = 'test'
    uid = '1234'
    database.set_module_label_to_flow(profileid,twid, uid, module_name, module_label )
    labels = database.get_module_labels_from_flow(profileid, twid, uid)
    assert labels ==  {'test': 'malicious'}

def test_setInfoForDomains(database):
    """ tests setInfoForDomains, setNewDomain and getDomainData """
    domain = 'www.google.com'
    domain_data = {'threatintelligence': 'sample data'}
    database.setInfoForDomains(domain,domain_data)

    stored_data = database.getDomainData(domain)
    assert  stored_data == {'threatintelligence': 'sample data'}

def test_subscribe(database):
    # invalid channel
    assert database.subscribe('invalid_channel') == False
    # valid channel, shoud return a pubsub object
    assert type(database.subscribe('tw_modified')) == redis.client.PubSub


def test_profile_moddule_labels(database):
    """ tests set and get_profile_module_label """
    module_label = 'malicious'
    module_name = 'test'
    database.set_profile_module_label(profileid, module_name, module_label )
    labels = database.get_profile_modules_labels(profileid)
    assert labels ==  {'test': 'malicious'}

