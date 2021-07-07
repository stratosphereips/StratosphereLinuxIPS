""" Unit test for modules/ThreatIntelligence1/threatintelligence-1.py """
from ..modules.ThreatIntelligence1.threatintelligence-1 import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_threatintel_instance(outputQueue):
    """ Create an instance of threatintel.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    threatintel = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    threatintel.print = do_nothing
    return threatintel

def test_get_hash_from_file(outputQueue, database):
    threatintel = create_threatintel_instance(outputQueue)
    # a file that we know doesn't change
    assert threatintel.__get_hash_from_file('../modules/template/__init__.py') == '2d12747a3369505a4d3b722a0422f8ffc8af5514355cdb0eb18178ea7071b8d0'
