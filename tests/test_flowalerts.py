""" Unit test for modules/flowalerts/flowalerts.py """
from ..modules.flowalerts.flowalerts import Module
import configparser

# dummy params used for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
uid = 'CAeDWs37BipkfP21u8'
timestamp = 1635765895.037696
saddr = '192.168.1.1'
daddr = '192.168.1.2'

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_flowalerts_instance(outputQueue):
    """ Create an instance of flowalerts.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    flowalerts = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    flowalerts.print = do_nothing
    return flowalerts

def test_check_long_connection(database, outputQueue):
	flowalerts = create_flowalerts_instance(outputQueue)
	# less than the threshold
	dur = '1400'  # in seconds
	database.add_flow(profileid=profileid,
					  twid=twid,
					  stime=timestamp,
					  dur=dur,
					  saddr= profileid.split('_'),
					  daddr= daddr,
					  uid=uid,
					  flow_type= 'conn')

	flowalerts.check_long_connection(dur,
									 daddr,
									 saddr,
									 profileid,
									 twid,
									 uid,
									 timestamp)
	module_labels = database.get_module_labels_from_flow(profileid, twid, uid)
	assert 'flowalerts-long-connection' in module_labels
	assert module_labels['flowalerts-long-connection'] == 'normal'

	# more than the threshold
	dur = 1600  # in seconds
	database.add_flow(profileid=profileid,
					  twid=twid,
					  stime=timestamp,
					  dur=dur,
					  saddr= profileid.split('_'),
					  daddr= daddr,
					  uid=uid,
					  flow_type= 'conn')

	flowalerts.check_long_connection(dur,
									 daddr,
									 saddr,
									 profileid,
									 twid,
									 uid,
									 timestamp)
	module_labels = database.get_module_labels_from_flow(profileid, twid, uid)
	assert 'flowalerts-long-connection' in module_labels
	assert module_labels['flowalerts-long-connection'] == 'malicious'


