""" Unit test for modules/http_analyzer/http_analyzer.py """
from ..modules.http_analyzer.http_analyzer import Module
import configparser

profileid = 'profile_192.168.1.1'
twid = 'timewindow1'

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_http_analyzer_instance(outputQueue):
    """ Create an instance of http_analyzer.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    http_analyzer = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    http_analyzer.print = do_nothing
    return http_analyzer

def test_check_suspicious_user_agents(outputQueue, database):
    http_analyzer = create_http_analyzer_instance(outputQueue)
    # create a flow with suspicious user agent
    uid = 'CAeDWs37BipkfP21u9'
    host = '147.32.80.7'
    uri = '/wpad.dat'
    user_agent =  'CHM_MSDN'
    timestamp = 1635765895.037696
    assert http_analyzer.check_suspicious_user_agents(uid, host, uri, timestamp, user_agent, profileid, twid) == True

def test_check_multiple_google_connections(outputQueue, database):
    http_analyzer = create_http_analyzer_instance(outputQueue)
    # {"ts":1635765765.435485,"uid":"C7mv0u4M1zqJBHydgj",
    # "id.orig_h":"192.168.1.28","id.orig_p":52102,"id.resp_h":"216.58.198.78",
    # "id.resp_p":80,"trans_depth":1,"method":"GET","host":"google.com","uri":"/",
    # "version":"1.1","user_agent":"Wget/1.20.3 (linux-gnu)","request_body_len":0,"response_body_len":219,
    # "status_code":301,"status_msg":"Moved Permanently","tags":[],"resp_fuids":["FGhwTU1OdvlfLrzBKc"],
    # "resp_mime_types":["text/html"]}
    uid = 'CAeDWs37BipkfP21u8'
    host = 'google.com'
    # uri = '/'
    timestamp = 1635765895.037696
    request_body_len = 0
    for i in range(4):
        found_detection = http_analyzer.check_multiple_empty_connections(uid, host, timestamp, request_body_len, profileid, twid)

    assert found_detection == True


