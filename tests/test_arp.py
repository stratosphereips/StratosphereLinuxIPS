"""Unit test for ../arp.py"""
from ..modules.arp.arp import Module
import uuid

# random values for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
prefix = 'f385579b-1c82-429e-bf61-a799adccab54'

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_ARP_instance(outputQueue, _prefix:str):
    """Create an instance of arp.py
    needed by every other test in this file"""
    ARP = Module(outputQueue, _prefix)
    # override the self.print function to avoid broken pipes
    ARP.print = do_nothing
    return ARP


# check_arp_scan is tested in test_dataset.py, check arp-only unit test
def test_check_dstip_outside_localnet(outputQueue, database):
    ARP = create_ARP_instance(outputQueue, prefix)
    daddr = '1.1.1.1'
    uid = '1234'
    saddr = '192.168.1.1'
    ts = '1632214645.783595'
    assert (
        ARP.check_dstip_outside_localnet(profileid, twid, daddr, uid, saddr, ts) is True
    )


def test_detect_unsolicited_arp(outputQueue, database):
    ARP = create_ARP_instance(outputQueue, prefix)
    uid = '1234'
    ts = '1632214645.783595'
    dst_mac = 'ff:ff:ff:ff:ff:ff'
    dst_hw = 'ff:ff:ff:ff:ff:ff'
    src_mac = '44:11:44:11:44:11'
    src_hw = '44:11:44:11:44:11'
    assert (
        ARP.detect_unsolicited_arp(profileid, twid, uid, ts, dst_mac, src_mac, dst_hw, src_hw) is True
    )


def test_detect_MITM_ARP_attack(outputQueue, database):
    ARP = create_ARP_instance(outputQueue, prefix)
    # add this profile to the database
    stime = ts = '1636305825.755100'
    dur = '3600.0'
    database.addProfile(profileid, stime, dur)

    # add a mac addr to this profile
    src_mac = '2e:a4:18:f8:3d:02'
    database.add_mac_addr_to_profile(profileid, {'MAC': src_mac})

    # now in this flow we have another ip  '192.168.1.3' pretending to have the same src_mac
    uid = '1234'
    ts = '1636305825.755132'
    saddr = '192.168.1.3'
    assert (
        ARP.detect_MITM_ARP_attack(profileid, twid, uid, saddr, ts, src_mac) is True
    )
    