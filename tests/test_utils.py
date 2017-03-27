import unittest
from utils import WhoisHandler


class TestWhoisHandler(unittest.TestCase):
    def setUp(self):
        # Using Github as dst ip
        self.w = WhoisHandler("WhoisData.txt")

    def test_get_whois_data(self):
        self.w.get_whois_data("192.30.253.112")
        self.assertEqual('GitHub, Inc.,US', self.w.whois_data['192.30.253.112'])

        # Add another one
        self.w.get_whois_data("193.212.4.21")
        self.assertIn('192.30.253.112', self.w.whois_data.keys())
        self.assertIn('193.212.4.21', self.w.whois_data.keys())

        # Test if the old one is still in the cache
        self.w.get_whois_data("192.30.253.112")
        self.assertIn('192.30.253.112', self.w.whois_data.keys())
