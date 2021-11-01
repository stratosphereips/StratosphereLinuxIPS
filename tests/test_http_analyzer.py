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
