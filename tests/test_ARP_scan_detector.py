""" Unit test for modules/ARP_scan_detector/ARP_scan_detector.py """
from ..modules.ARP_scan_detector.ARP_scan_detector import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_ARP_scan_detector_instance(outputQueue):
    """ Create an instance of ARP_scan_detector.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    ARP_scan_detector = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    ARP_scan_detector.print = do_nothing
    return ARP_scan_detector

def test_check_arp_scan(database, outputQueue):
    ARP_scan_detector = create_ARP_scan_detector_instance(outputQueue)
    # this function sets evidence every 10 arp requests from the same ip.
    for i in range(10):
        # sample flow
        flow = {'uid': 'NmQxZjYzMTIzYzNhZDlhOTBk', 'daddr': '192.168.1.4', 'saddr': '192.168.1.10', 'src_mac': '123',
            'dst_mac': 'ff:ff:ff:ff:ff:ff', 'ts': 1629108378.380464+i, 'profileid': 'profile_192.168.1.10', 'twid': 'timewindow1'}
        arp_scan_detected = ARP_scan_detector.check_arp_scan(flow)
    assert ARP_scan_detector.diff > 0.015
    assert arp_scan_detected == True