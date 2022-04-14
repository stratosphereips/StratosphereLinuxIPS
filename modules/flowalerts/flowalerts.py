# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
from .TimerThread import TimerThread

# Your imports
import json
import configparser
import ipaddress
import datetime
import time
import sys
import socket
import validators
from .set_evidence import Helper

class Module(Module, multiprocessing.Process):
    name = 'flowalerts'
    description = 'Alerts about flows: long connection, successful ssh, ' \
                  'password guessing, self-signed certificate, data exfiltration, etc.'
    authors = ['Kamila Babayeva', 'Sebastian Garcia', 'Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Read the configuration
        self.read_configuration()
        # Retrieve the labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        self.c1 = __database__.subscribe('new_flow')
        self.c2 = __database__.subscribe('new_ssh')
        self.c3 = __database__.subscribe('new_notice')
        self.c4 = __database__.subscribe('new_ssl')
        self.c5 = __database__.subscribe('new_service')
        self.c6 = __database__.subscribe('new_dns_flow')
        self.c7 = __database__.subscribe('new_downloaded_file')
        self.c8 = __database__.subscribe('new_smtp')
        # helper contains all functions used to set evidence
        self.helper = Helper()
        self.timeout = 0.0000001
        self.p2p_daddrs = {}
        # get the default gateway
        self.gateway = __database__.get_default_gateway()
        # Cache list of connections that we already checked in the timer
        # thread (we waited for the connection of these dns resolutions)
        self.connections_checked_in_dns_conn_timer_thread = []
        # Cache list of connections that we already checked in the timer
        # thread (we waited for the dns resolution for these connections)
        self.connections_checked_in_conn_dns_timer_thread = []
        # Cache list of connections that we already checked in the timer thread for ssh check
        self.connections_checked_in_ssh_timer_thread = []
        # Threshold how much time to wait when capturing in an interface, to start reporting connections without DNS
        # Usually the computer resolved DNS already, so we need to wait a little to report
        # In seconds
        self.conn_without_dns_interface_wait_time = 1800
        # this dict will contain the number of nxdomains found in every profile
        self.nxdomains = {}
        # if nxdomains are >= this threshold, it's probably DGA
        self.nxdomains_threshold = 10
        # when the ctr reaches the threshold in 10 seconds, we detect an smtp bruteforce
        self.smtp_bruteforce_threshold = 3
        # dict to keep track of bad smtp logins to check for bruteforce later
        # format {profileid: [ts,ts,...]}
        self.smtp_bruteforce_cache = {}
        # dict to keep track of arpa queries to check for DNS arpa scans later
        # format {profileid: [ts,ts,...]}
        self.dns_arpa_queries = {}
        # after this number of arpa queries, slips will detect an arpa scan
        self.arpa_scan_threshold = 10
        self.x= ['64.20.34.50', '114.34.116.139', '54.155.209.93', '195.238.187.150', '139.59.223.113', '95.211.44.91', '139.199.33.37', '45.90.29.229', '92.63.170.105', '213.183.62.11', '188.172.251.1', '45.90.29.196', '45.90.30.132', '45.90.28.93', '45.90.28.49', '80.124.140.163', '140.207.198.6', '80.124.140.231', '217.66.37.27', '17.253.36.85', '196.20.72.29', '104.225.11.200', '45.90.30.161', '54.69.221.253', '185.43.135.1', '52.17.180.181', '45.90.30.10', '17.253.26.85', '23.94.120.177', '17.253.84.247', '160.119.253.209', '74.82.42.42', '80.125.181.174', '140.82.59.231', '34.72.159.240', '45.90.28.8', '45.90.30.215', '203.162.172.59', '45.90.29.0', '159.69.108.26', '109.24.72.34', '152.67.229.20', '83.69.169.69', '94.130.182.199', '168.235.64.166', '149.28.161.146', '45.90.28.208', '45.32.47.13', '45.90.28.82', '203.180.146.24', '210.128.97.74', '130.89.162.82', '67.8.56.46', '109.24.70.47', '51.79.173.140', '121.196.195.196', '202.232.2.33', '80.125.180.155', '45.90.28.198', '45.90.28.76', '178.18.54.141', '210.130.0.70', '192.73.240.126', '80.124.140.166', '194.50.94.140', '185.12.88.92', '80.125.181.179', '45.90.30.9', '45.76.106.139', '128.139.197.53', '45.90.28.226', '45.90.28.84', '213.61.254.42', '92.63.32.3', '209.177.158.15', '17.253.12.215', '80.125.181.183', '45.125.0.88', '46.101.126.246', '89.17.159.213', '210.128.97.88', '45.90.30.15', '80.254.77.39', '45.90.30.190', '17.253.82.213', '39.103.26.198', '37.252.225.79', '95.216.161.62', '45.90.29.197', '45.90.28.243', '81.7.14.83', '180.163.223.236', '45.90.28.141', '8.39.235.108', '45.90.28.220', '204.15.75.156', '45.90.29.119', '17.253.24.213', '80.125.161.117', '17.253.124.247', '52.34.132.225', '34.96.142.40', '45.90.30.78', '162.250.7.137', '45.77.137.133', '45.90.29.191', '45.90.30.189', '45.90.30.174', '106.11.37.109', '173.212.232.112', '52.31.171.166', '45.151.175.112', '45.90.30.18', '45.90.28.68', '47.103.166.50', '47.103.166.56', '45.90.28.224', '45.90.28.120', '45.35.154.2', '45.90.30.120', '8.8.4.4', '45.90.29.211', '45.90.28.235', '45.125.0.53', '45.90.28.59', '210.128.97.217', '45.90.30.113', '119.147.179.244', '45.90.30.245', '152.67.199.120', '104.225.11.199', '217.146.107.8', '107.174.206.189', '62.12.117.34', '203.180.146.13', '45.90.28.207', '116.63.136.113', '45.90.29.193', '184.31.0.235', '45.90.28.164', '45.90.30.6', '45.90.30.191', '39.98.133.171', '101.198.198.198', '209.177.158.226', '45.90.28.122', '80.124.140.206', '116.202.103.81', '45.90.29.223', '47.108.130.22', '140.238.3.36', '45.90.29.169', '208.111.39.77', '45.90.30.123', '147.230.16.240', '210.128.97.204', '135.181.102.167', '80.124.140.240', '45.90.29.105', '213.61.254.36', '45.90.29.148', '80.254.79.157', '45.90.29.75', '149.112.121.30', '45.90.30.188', '80.125.161.177', '45.90.29.103', '45.90.30.192', '45.90.30.146', '168.235.81.167', '51.81.224.232', '88.215.65.27', '45.90.30.129', '45.90.29.118', '194.191.40.98', '45.90.29.106', '217.146.11.49', '44.234.219.208', '45.90.28.160', '52.18.44.241', '45.90.28.212', '159.100.248.193', '203.180.146.203', '45.90.30.96', '45.90.30.124', '3.232.78.158', '52.49.195.5', '45.90.28.148', '202.232.2.31', '69.70.16.42', '45.90.30.8', '3.224.109.152', '51.222.107.153', '45.90.29.129', '80.124.140.157', '34.101.84.129', '52.43.41.34', '93.115.24.205', '45.90.29.245', '193.106.119.10', '45.90.30.221', '45.90.28.132', '54.171.175.41', '143.244.33.74', '210.128.97.78', '45.90.28.118', '195.228.221.132', '45.90.28.149', '142.93.33.36', '64.64.248.141', '168.95.1.1', '45.90.30.173', '170.176.145.150', '51.140.100.181', '45.90.28.67', '44.229.182.61', '63.116.30.36', '180.163.223.233', '185.185.69.93', '1.0.0.2', '45.90.29.177', '34.73.73.224', '45.90.30.19', '192.109.42.42', '128.199.94.194', '80.125.180.156', '194.204.251.11', '54.194.121.142', '107.182.22.203', '45.90.28.37', '45.90.29.86', '216.98.99.110', '131.100.2.149', '17.253.24.247', '80.125.161.86', '39.100.20.1', '45.90.29.128', '45.90.29.209', '45.90.30.65', '195.228.221.3', '45.90.28.88', '176.223.136.169', '54.95.198.208', '45.90.29.14', '210.130.0.1', '210.130.0.53', '45.90.28.45', '121.199.79.161', '134.102.20.20', '199.38.182.12', '45.90.29.225', '54.169.113.231', '178.32.196.195', '172.83.159.59', '194.62.167.148', '45.90.28.223', '172.107.93.122', '213.183.62.162', '195.161.115.16', '210.138.123.76', '5.34.180.247', '89.187.169.24', '82.165.97.135', '165.232.130.184', '119.3.218.92', '217.160.25.182', '45.90.28.70', '80.124.140.233', '45.90.28.75', '17.253.82.119', '140.238.220.58', '210.130.0.21', '45.77.229.157', '159.203.35.192', '140.238.215.120', '185.12.88.179', '217.0.43.50', '210.128.97.76', '45.132.75.16', '209.208.26.145', '45.90.30.44', '45.90.30.141', '223.5.5.5', '140.238.228.220', '180.163.249.75', '80.124.140.168', '45.90.28.182', '207.154.225.150', '37.120.149.148', '199.38.182.187', '109.2.202.236', '45.90.29.251', '106.11.37.100', '5.1.32.213', '80.124.140.144', '45.90.28.14', '210.130.1.3', '45.90.30.166', '8.131.52.117', '44.238.109.133', '45.90.28.246', '44.233.140.212', '194.204.251.13', '20.42.80.49', '212.26.128.3', '45.90.28.181', '173.243.64.102', '213.61.254.41', '45.90.30.138', '116.203.115.225', '45.90.29.36', '161.210.250.2', '45.90.29.17', '68.183.70.223', '45.90.29.23', '31.187.64.235', '45.90.29.123', '194.191.40.97', '78.142.193.36', '45.90.30.198', '24.134.187.45', '49.229.0.46', '52.31.191.149', '45.90.28.154', '193.9.112.136', '45.90.28.71', '3.7.176.123', '155.138.142.93', '45.90.29.25', '104.225.11.36', '45.90.29.12', '194.100.93.136', '103.219.152.6', '83.69.169.222', '193.191.129.46', '45.90.29.171', '185.183.159.34', '86.0.64.55', '206.189.185.210', '45.90.28.159', '158.101.195.71', '161.35.28.190', '45.90.28.95', '45.90.30.5', '45.90.28.167', '45.90.29.155', '45.90.30.157', '216.230.232.29', '37.235.49.73', '45.90.28.57', '45.90.29.234', '217.31.204.205', '45.90.30.12', '167.179.64.116', '45.90.29.179', '173.199.126.35', '185.233.104.206', '80.125.181.186', '45.90.29.99', '75.75.77.24', '45.90.29.8', '119.28.59.205', '54.172.110.180', '104.225.11.172', '23.100.95.102', '200.25.36.70', '82.118.227.235', '80.125.180.65', '45.90.30.46', '34.66.70.56', '45.90.28.239', '140.238.159.230', '34.197.6.94', '168.119.160.80', '17.253.96.85', '45.90.30.177', '8.208.2.64', '80.251.225.218', '45.90.29.33', '67.230.177.135', '176.31.83.186', '104.225.11.245', '80.124.140.201', '81.7.14.191', '45.90.28.201', '45.90.28.96', '45.77.162.235', '185.56.27.1', '77.223.128.220', '176.126.70.229', '195.50.204.191', '36.99.170.86', '45.90.30.169', '82.148.223.195', '80.125.161.67', '17.253.12.247', '185.88.160.25', '80.125.180.165', '104.225.12.24', '45.90.28.199', '104.198.99.225', '139.99.134.6', '212.227.205.78', '52.19.206.74', '45.117.103.234', '170.39.227.247', '208.111.35.106', '82.165.167.96', '47.108.0.58', '80.149.229.107', '45.90.28.101', '52.16.163.185', '45.90.30.7', '155.138.148.63', '149.112.112.12', '140.82.45.97', '213.139.211.36', '193.191.129.45', '103.196.38.40', '45.90.30.158', '70.113.111.13', '103.6.212.123', '45.90.28.12', '80.251.201.59', '45.90.30.222', '191.209.16.235', '134.102.20.26', '203.180.146.208', '109.24.72.14', '157.245.36.211', '45.90.30.84', '45.90.29.125', '31.216.14.41', '193.170.194.22', '87.98.175.85', '185.21.100.14', '45.90.30.99', '35.229.69.83', '176.58.90.11', '109.24.70.11', '45.90.30.232', '45.90.30.147', '9.9.9.11', '3.209.17.34', '116.202.244.138', '45.90.28.106', '45.90.30.11', '47.108.0.39', '185.235.81.1', '149.112.112.10', '221.181.72.233', '193.150.121.28', '74.63.24.248', '45.77.223.173', '80.124.140.164', '45.90.29.120', '217.0.43.66', '89.233.43.71', '45.131.68.246', '45.90.29.114', '109.24.72.11', '45.90.29.217', '210.138.123.109', '80.125.180.95', '119.28.63.83', '45.90.30.77', '45.90.29.203', '144.172.119.31', '185.26.125.181', '185.140.250.174', '54.246.187.60', '210.130.0.3', '5.188.168.252', '49.229.0.115', '80.124.140.238', '45.90.29.67', '139.199.193.210', '45.90.30.197', '81.7.14.215', '83.212.102.207', '192.73.244.179', '45.90.28.121', '205.147.105.156', '45.90.30.203', '134.209.81.226', '80.125.161.90', '17.253.56.213', '45.60.186.33', '154.121.2.53', '45.90.28.9', '45.90.28.191', '45.90.28.103', '91.230.211.67', '35.229.156.160', '80.125.181.116', '45.90.28.64', '17.253.56.85', '45.90.30.47', '147.162.22.1', '140.238.174.12', '223.5.5.109', '45.90.29.233', '107.162.133.99', '80.125.181.80', '194.87.239.59', '188.172.192.71', '45.90.29.79', '78.47.105.4', '78.128.99.220', '202.232.2.38', '217.169.20.23', '45.90.29.204', '45.90.30.22', '45.90.30.52', '82.165.247.205', '45.90.30.162', '91.212.238.8', '185.244.195.159', '45.90.29.50', '45.90.30.250', '110.43.53.226', '217.146.1.31', '35.227.19.85', '213.61.254.39', '185.103.117.76', '176.103.130.137', '130.61.69.193', '217.160.249.29', '136.244.79.94', '45.90.29.195', '210.128.97.222', '210.246.144.15', '80.125.161.108', '17.253.82.247', '45.90.28.236', '37.252.254.39', '45.90.30.57', '45.90.30.160', '45.90.28.5', '45.90.29.141', '210.128.97.85', '45.90.28.237', '45.90.28.170', '52.41.109.236', '45.90.30.81', '176.125.239.22', '47.103.166.53', '193.190.182.53', '149.129.124.211', '207.148.95.1', '8.208.2.65', '156.251.165.134', '194.191.40.86', '45.90.30.195', '138.197.159.48', '80.125.181.71', '80.125.181.99', '45.90.29.212', '45.90.28.110', '82.64.163.190', '9.9.9.9', '200.25.57.69', '93.180.70.22', '5.79.100.76', '17.253.34.247', '23.209.73.136', '39.103.26.199', '45.90.29.85', '1.192.192.206', '75.2.118.36', '45.90.29.15', '141.84.69.29', '176.103.130.136', '195.244.44.45', '45.77.154.135', '101.36.166.17', '45.90.28.214', '210.138.123.111', '103.149.46.217', '45.90.30.92', '106.11.37.96', '104.225.12.146', '45.90.29.167', '45.90.28.13', '84.21.7.14', '45.90.28.230', '45.90.28.197', '130.59.31.248', '45.90.28.134', '176.58.88.213', '45.90.29.90', '45.32.219.28', '93.189.61.195', '52.55.49.18', '85.145.222.167', '86.109.1.91', '90.145.32.35', '37.252.247.133', '45.90.28.232', '109.24.72.41', '45.90.29.47', '45.90.28.206', '34.247.230.158', '82.64.205.253', '61.148.33.140', '149.112.112.13', '45.90.30.214', '45.90.30.31', '54.237.181.250', '185.210.2.71', '161.97.79.138', '175.24.154.191', '210.138.123.78', '3.208.47.162', '45.90.28.242', '91.212.238.14', '47.103.18.1', '52.48.147.197', '45.90.28.173', '185.235.81.3', '141.100.59.223', '45.90.30.225', '80.125.181.123', '54.73.239.183', '80.125.180.125', '209.208.110.56', '45.90.28.99', '45.90.29.62', '45.90.28.62', '45.90.28.91', '198.23.209.146', '168.138.250.131', '5.39.88.20', '80.124.140.239', '81.7.14.52', '45.90.28.66', '31.216.14.42', '66.42.70.192', '45.90.28.41', '116.203.30.98', '103.196.38.38', '45.90.29.13', '103.247.37.150', '222.124.173.197', '185.244.27.53', '80.125.180.73', '45.90.28.172', '45.90.29.190', '107.20.123.160', '45.90.29.181', '18.210.8.52', '165.22.46.136', '45.90.28.90', '54.79.3.18', '130.255.78.51', '202.232.2.32', '104.225.12.223', '192.73.252.11', '45.90.29.7', '45.90.28.107', '217.0.43.2', '149.112.121.20', '45.90.30.170', '45.90.30.252', '222.88.72.38', '130.61.93.4', '37.252.239.39', '87.106.168.61', '51.158.66.31', '199.38.182.47', '75.75.77.6', '45.90.29.93', '101.101.101.101', '195.91.66.55', '80.124.140.131', '45.90.30.62', '17.253.6.85', '45.90.28.78', '209.177.158.142', '94.16.114.254', '149.112.149.112', '45.90.30.136', '45.90.30.149', '80.125.180.124', '109.24.70.2', '45.90.30.109', '45.90.28.16', '35.211.162.236', '167.6.236.224', '91.212.238.22', '193.190.198.16', '45.90.29.16', '86.106.90.57', '45.90.28.115', '45.90.28.211', '17.253.16.119', '79.110.170.43', '109.24.72.150', '91.239.27.199', '95.217.213.94', '17.253.2.247', '103.123.164.2', '45.90.30.3', '132.145.80.242', '45.90.30.107', '45.90.28.80', '210.130.0.51', '161.97.171.39', '188.34.186.98', '185.247.117.121', '80.125.181.13', '93.115.24.204', '80.125.181.98', '185.12.88.178', '193.191.129.41', '96.17.108.202', '46.101.66.244', '45.90.29.35', '106.14.221.10', '138.201.246.200', '124.70.83.172', '217.146.31.87', '188.172.213.149', '80.124.140.221', '209.177.158.248', '80.125.181.185', '5.1.32.212', '141.84.69.2', '210.138.123.74', '45.90.30.80', '52.42.217.166', '72.11.134.91', '35.223.113.18', '92.223.65.71', '149.154.157.148', '54.72.41.135', '128.93.162.64', '3.128.212.186', '194.191.40.100', '45.90.29.214', '116.203.141.185', '45.90.28.79', '45.90.28.163', '104.225.216.146', '80.125.161.105', '45.90.28.39', '111.206.170.220', '45.90.28.253', '209.177.145.66', '66.42.50.16', '40.114.217.81', '80.125.161.172', '217.169.20.22', '45.90.30.150', '3.121.138.96', '213.149.240.21', '81.7.14.85', '45.90.28.28', '185.229.226.28', '45.90.29.188', '45.90.29.131', '217.160.44.149', '45.90.28.150', '108.40.78.219', '142.93.248.50', '95.216.74.67', '124.70.72.126', '81.7.14.252', '210.138.123.105', '45.90.28.117', '185.210.2.70', '210.128.97.83', '45.90.28.7', '111.206.170.78', '45.90.30.83', '109.27.84.62', '45.90.29.207', '80.124.140.200', '47.100.218.41', '45.90.30.253', '140.238.28.191', '45.90.29.132', '194.249.0.142', '45.90.28.249', '45.90.30.91', '95.216.209.165', '172.81.108.146', '37.139.26.4', '210.138.123.75', '45.90.28.43', '81.7.14.159', '160.16.53.149', '158.64.1.29', '45.90.28.222', '213.149.105.9', '143.244.33.90', '185.255.55.25', '203.180.146.12', '45.131.68.245', '45.90.30.74', '185.253.154.66', '47.244.3.29', '45.79.120.233', '75.2.80.144', '45.90.30.226', '45.90.28.166', '104.225.8.147', '45.90.28.52', '202.218.2.19', '185.150.10.229', '80.125.181.124', '79.143.240.7', '44.237.198.74', '109.24.70.70', '116.203.131.110', '45.90.30.238', '185.40.106.78', '184.31.0.240', '192.73.240.168', '14.192.49.53', '45.90.28.203', '45.90.30.32', '17.253.26.119', '80.125.180.161', '3.9.78.39', '8.129.77.255', '212.86.101.213', '52.215.49.128', '82.165.23.176', '86.159.144.0', '45.90.29.44', '45.90.28.2', '45.90.28.24', '17.253.24.85', '45.90.28.228', '54.189.234.230', '116.204.183.61', '45.90.29.27', '130.59.31.251', '34.65.12.198', '47.254.160.160', '194.39.205.162', '45.90.29.248', '95.216.187.185', '45.90.29.142', '80.124.140.207', '180.163.223.231', '75.75.77.5', '172.65.220.168', '45.90.29.116', '210.128.97.215', '54.227.13.144', '116.12.51.216', '18.216.182.207', '107.172.90.160', '17.253.30.85', '45.90.30.0', '80.125.180.154', '5.59.130.114', '217.138.209.217', '45.90.28.127', '80.251.195.73', '193.122.96.153', '47.103.166.51', '91.217.86.4', '45.90.29.149', '176.58.92.236', '45.90.29.100', '193.17.47.1', '17.253.22.247', '149.129.239.2', '52.209.174.126', '45.90.28.36', '47.108.0.45', '72.44.68.88', '193.180.80.10', '151.181.237.20', '45.90.28.38', '194.87.94.229', '210.138.123.79', '161.210.250.7', '45.90.28.152', '45.90.30.239', '188.241.178.104', '88.98.88.158', '162.14.132.76', '217.173.235.78', '51.81.81.178', '9.9.9.10', '161.210.250.8', '45.90.29.174', '80.125.180.100', '17.253.124.119', '17.253.38.243', '72.11.134.90', '31.216.6.41', '75.75.77.25', '158.101.2.228', '86.106.103.153', '45.90.30.76', '80.124.140.160', '149.112.122.30', '45.90.28.25', '80.125.161.184', '147.135.109.96', '91.239.96.21', '45.90.28.105', '152.89.161.16', '101.198.199.200', '167.71.190.157', '213.61.254.44', '45.90.29.244', '45.90.29.180', '216.119.155.49', '17.253.66.247', '101.32.30.247', '108.61.189.69', '45.90.28.126', '91.191.170.21', '94.140.15.15', '199.38.181.200', '80.124.140.129', '178.255.153.47', '162.250.2.3', '45.90.30.35', '86.73.221.179', '52.44.142.142', '3.248.149.109', '203.204.102.17', '5.1.32.33']


    def is_ignored_ip(self, ip) -> bool:
        """
        This function checks if an IP is an special list of IPs that
        should not be alerted for different reasons
        """
        try:
            ip_obj =  ipaddress.ip_address(ip)
            # Is the IP multicast, private? (including localhost)
            # local_link or reserved?
            # The broadcast address 255.255.255.255 is reserved.
            if ip_obj.is_multicast or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved or '.255' in ip_obj.exploded:
                return True
            return False
        except Exception as inst:
            self.print('Problem on function is_ignored_ip()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return False

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the pcap filter
        try:
            self.long_connection_threshold = int(self.config.get('flowalerts', 'long_connection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # this value is in seconds, =25 mins
            self.long_connection_threshold = 1500
        try:
            self.ssh_succesful_detection_threshold = int(self.config.get('flowalerts', 'ssh_succesful_detection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ssh_succesful_detection_threshold = 4290
        try:
            self.data_exfiltration_threshold = int(self.config.get('flowalerts', 'data_exfiltration_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # threshold in MBs
            self.data_exfiltration_threshold = 700

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def check_long_connection(self, dur, daddr, saddr, profileid, twid, uid, timestamp):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutess by default).
        :param dur: duration of the flow in seconds
        """
        if type(dur) == str:
            dur = float(dur)
        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
            # set "flowalerts-long-connection:malicious" label in the flow (needed for Ensembling module)
            module_name = "flowalerts-long-connection"
            module_label = self.malicious_label

            __database__.set_module_label_to_flow(profileid,
                                                  twid,
                                                  uid,
                                                  module_name,
                                                  module_label)
            self.helper.set_evidence_long_connection(daddr, dur, profileid, twid, uid, timestamp, ip_state='ip')
        else:
            # set "flowalerts-long-connection:normal" label in the flow (needed for Ensembling module)
            module_name = "flowalerts-long-connection"
            module_label = self.normal_label
            __database__.set_module_label_to_flow(profileid,
                                                  twid,
                                                  uid,
                                                  module_name,
                                                  module_label)

    def is_p2p(self, dport, proto, daddr):
        """
        P2P is defined as following : proto is udp, port numbers are higher than 30000 at least 5 connections to different daddrs
        OR trying to connct to 1 ip on more than 5 unkown 30000+/udp ports
        """
        if proto.lower() == 'udp' and int(dport)>30000:
            try:
                # trying to connct to 1 ip on more than 5 unknown ports
                if self.p2p_daddrs[daddr] >= 6:
                    return True
                self.p2p_daddrs[daddr] = self.p2p_daddrs[daddr] +1
                # now check if we have more than 4 different dst ips
            except KeyError:
                # first time seeing this daddr
                self.p2p_daddrs[daddr] = 1

            if len(self.p2p_daddrs) == 5:
                # this is another connection on port 3000+/udp and we already have 5 of them
                # probably p2p
                return True

        return False


    def port_belongs_to_an_org(self, daddr, portproto, profileid):
        """
        Checks weather a port is known to be used by a specific organization or not
        """
        organization_info = __database__.get_organization_of_port(portproto)
        if organization_info:
            # there's an organization that's known to use this port,
            # check if the daddr belongs to the range of this org
            organization_info = json.loads(organization_info)
            # get the organization ip or range
            org_ip = organization_info['ip']
            # org_name = organization_info['org_name']

            if daddr in org_ip:
                # it's an ip and it belongs to this org, consider the port as known
                return False

            # is it a range?
            try:
                # we have the org range in our database, check if the daddr belongs to this range
                if ipaddress.ip_address(daddr) in ipaddress.ip_network(org_ip):
                    # it does, consider the port as known
                    return False
            except ValueError:
                # not a range either since nothing is specified,
                # check the source and dst mac address vendors
                src_mac_vendor = str(__database__.get_mac_vendor_from_profile(profileid))
                dst_mac_vendor = str(__database__.get_mac_vendor_from_profile(f'profile_{daddr}'))
                org_name = organization_info['org_name'].lower()
                if (org_name in src_mac_vendor.lower()
                        or org_name in dst_mac_vendor.lower()):
                    return True
                else:
                    # check if the SNI, hostname, rDNS of this ip belong to org_name
                    ip_identification = __database__.getIPIdentification(daddr)
                    if org_name in ip_identification.lower():
                        return True

        # consider this port as unknown
        return False

    def check_unknown_port(self, dport, proto, daddr, profileid, twid, uid, timestamp):
        """ Checks dports that are not in our slips_files/ports_info/ files"""
        portproto = f'{dport}/{proto}'
        port_info = __database__.get_port_info(portproto)
        if port_info:
            # it's a known port
            return False
        # we don't have port info in our database
        # is it a port that is known to be used by a specific organization
        if self.port_belongs_to_an_org(daddr, portproto, profileid):
            return False


        if (not 'icmp' in proto
            and not self.is_p2p(dport, proto, daddr)
            and not __database__.is_ftp_port(dport)):
            # we don't have info about this port
            self.helper.set_evidence_unknown_port(daddr, dport, proto, timestamp, profileid, twid, uid)

    def check_if_resolution_was_made_by_different_version(self, profileid, daddr):
        """
        Sometimes the same computer makes dns requests using its ipv4 and ipv6 address, check if this is the case
        """
        # get the other ip version of this computer
        other_ip = __database__.get_the_other_ip_version(profileid)
        # get info about the dns resolution of this connection
        dns_resolution = __database__.get_dns_resolution(daddr)

        try:
            if other_ip and other_ip in dns_resolution.get('resolved-by', []):
                return True
        except AttributeError:
            # It can be that the dns_resolution sometimes gives back a list and gets this error
            return False

    def check_if_connection_was_made_by_different_version(self, profileid, twid, daddr):
        """
        :param daddr: the ip this connection is made to (destination ip)
        """
        # get the other ip version of this computer
        other_ip = __database__.get_the_other_ip_version(profileid)
        if not other_ip:
            return False

        # get the ips contacted by the other_ip
        contacted_ips = __database__.get_all_contacted_ips_in_profileid_twid(f'profileid_{other_ip}', twid)
        if not contacted_ips:
            return False

        if daddr in contacted_ips:
            # now we're sure that the connection was made
            # by this computer but using a different ip version
            return True

    def check_dns_arpa_scan(self, domain, stime, profileid, twid, uid):
        """
        Detect and ARPA scan if an ip performed 10(arpa_scan_threshold) or more arpa queries within 2 seconds
        """
        if not domain.endswith('.in-addr.arpa'):
            return False

        try:
            # format of this dict is {profileid: [stime of first arpa query, stim eof second, etc..]}
            self.dns_arpa_queries[profileid].append(stime)
        except KeyError:
            # first time for this profileid to perform an arpa query
            self.dns_arpa_queries[profileid] = [stime]

        if not len(self.dns_arpa_queries[profileid]) >= self.arpa_scan_threshold:
            # didn't reach the threshold yet
            return False

        # reached the threshold, did the 10 quries happen within 2 seconds?
        diff = self.dns_arpa_queries[profileid][-1] - self.dns_arpa_queries[profileid][0]
        if not diff <= 2:
            # happened within more than 2 seconds
            return False

        self.helper.set_evidence_dns_arpa_scan(self.arpa_scan_threshold, stime, profileid, twid, uid)
        # empty the list of arpa queries timestamps, we don't need thm anymore
        self.dns_arpa_queries[profileid] = []

    def is_well_known_org(self, ip):
        """get the SNI, ASN, and  rDNS of the IP to check if it belongs
         to a well-known org"""
        supported_orgs = ('google', 'microsoft', 'apple', 'facebook', 'twitter')
        ip_data = __database__.getIPData(ip)
        try:
            ip_asn = ip_data['asn']['asnorg']
        except (KeyError, TypeError):
            # No asn data for this ip
            ip_asn = False

        try:
            SNI = ip_data['SNI']
            if type(SNI) == list:
                SNI = SNI[0]
                if SNI in (None, ''):
                    SNI = False
        except (KeyError, TypeError):
            # No SNI data for this ip
            SNI = False

        try:
            rdns = ip_data['reverse_dns']
        except (KeyError, TypeError):
            # No SNI data for this ip
            rdns = False

        flow_domain = rdns or SNI
        for org in supported_orgs:
            if ip_asn and ip_asn != 'Unknown':
                org_asn = json.loads(__database__.get_org_info(org, 'asn'))
                if org.lower() in ip_asn.lower() or ip_asn in org_asn:
                    return True
            # remove the asn from ram
            org_asn = ''
            if flow_domain:
                # we have the rdns or sni of this flow , now check
                if org in flow_domain:
                    # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
                    return True

                org_domains = json.loads(__database__.get_org_info(org, 'domains'))

                flow_TLD = flow_domain.split(".")[-1]
                for org_domain in org_domains:
                    org_domain_TLD = org_domain.split(".")[-1]
                    # make sure the 2 domains have the same same top level domain
                    if flow_TLD != org_domain_TLD:
                        continue

                    # match subdomains too
                    # return true if org has org.com, and the flow_domain is xyz.org.com
                    # or if org has xyz.org.com, and the flow_domain is org.com return true
                    if org_domain in flow_domain or flow_domain in org_domain :
                        return True

                # remove from ram
                org_domains = ''

            org_ips = json.loads(__database__.get_org_info(org, 'IPs'))
            if ip in org_ips:
                return True


    def check_connection_without_dns_resolution(self, daddr, twid, profileid, timestamp, uid):
        """ Checks if there's a flow to a dstip that has no cached DNS answer """

        # Ignore some IP
        ## - All dhcp servers. Since is ok to connect to them without a DNS request.
        # We dont have yet the dhcp in the redis, when is there check it
        #if __database__.get_dhcp_servers(daddr):
            #continue

        # to avoid false positives in case of an interface don't alert
        # ConnectionWithoutDNS until 2 minutes has passed
        # after starting slips because the dns may have happened before starting slips
        if '-i' in sys.argv:
            start_time = __database__.get_slips_start_time()
            now = datetime.datetime.now()
            diff = now - start_time
            diff = diff.seconds
            if not int(diff) >= 120:
                # less than 2 minutes have passed
                return False

        answers_dict = __database__.get_dns_resolution(daddr)
        if not answers_dict:
            #self.print(f'No DNS resolution in {answers_dict}')
            # There is no DNS resolution, but it can be that Slips is
            # still reading it from the files.
            # To give time to Slips to read all the files and get all the flows
            # don't alert a Connection Without DNS until 5 seconds has passed
            # in real time from the time of this checking.

            # Create a timer thread that will wait 5 seconds for the dns to arrive and then check again
            #self.print(f'Cache of conns not to check: {self.conn_checked_dns}')
            if uid not in self.connections_checked_in_conn_dns_timer_thread:
                # comes here if we haven't started the timer thread for this connection before
                # mark this connection as checked
                self.connections_checked_in_conn_dns_timer_thread.append(uid)
                params = [daddr, twid, profileid, timestamp, uid]
                #self.print(f'Starting the timer to check on {daddr}, uid {uid}.
                # time {datetime.datetime.now()}')
                timer = TimerThread(15, self.check_connection_without_dns_resolution, params)
                timer.start()
            elif uid in self.connections_checked_in_conn_dns_timer_thread:
                # It means we already checked this conn with the Timer process
                # (we waited 15 seconds for the dns to arrive after the connection was made)
                # but still no dns resolution for it.
                # Sometimes the same computer makes requests using its ipv4 and ipv6 address, check if this is the case
                if self.check_if_resolution_was_made_by_different_version(profileid, daddr):
                    return False

                if self.is_well_known_org(daddr):
                    # if the SNI or rDNS of the IP matches a well-known org, then this is a FP
                    return False
                #self.print(f'Alerting after timer conn without dns on {daddr},
                self.helper.set_evidence_conn_without_dns(daddr, timestamp, profileid, twid, uid)
                # This UID will never appear again, so we can remove it and
                # free some memory
                try:
                    self.connections_checked_in_conn_dns_timer_thread.remove(uid)
                except ValueError:
                    pass

    def check_dns_resolution_without_connection(self, domain, answers, timestamp, profileid, twid, uid):
        """
        Makes sure all cached DNS answers are used in contacted_ips
        :param contacted_ips:  dict of ips used in a specific tw {ip: uid}
        """
        # Ignore some domains because its is ok if they do DNS without a connection
        ## - All reverse dns resolutions
        ## - All .local domains
        ## - The wildcard domain *
        ## - Subdomains of cymru.com, since it is used by the ipwhois library in Slips to get the ASN of an IP and its range. This DNS is meant not to have a connection later
        ## - Domains check from Chrome, like xrvwsrklpqrw
        ## - The WPAD domain of windows

        if ('arpa' in domain
                or '.local' in domain
                or '*' in domain
                or '.cymru.com' in domain[-10:]
                or len(domain.split('.')) == 1
                or domain == 'WPAD'):
            return False

        # One DNS query may not be answered exactly by UID, but the computer can re-ask the donmain, and the next DNS resolution can be
        # answered. So dont check the UID, check if the domain has an IP

        #self.print(f'The DNS query to {domain} had as answers {answers} ')

        # It can happen that this domain was already resolved previously, but with other IPs
        # So we get from the DB all the IPs for this domain first and append them to the answers
        # This happens, for example, when there is 1 DNS resolution with A, then 1 DNS resolution
        # with AAAA, and the computer chooses the A address. Therefore, the 2nd DNS resolution
        # would be treated as 'without connection', but this is false.

        previous_data_for_domain =  __database__.getDomainData(domain)
        if previous_data_for_domain:
            try:
                previous_ips_for_domain =  previous_data_for_domain['IPs']
                answers.extend(previous_ips_for_domain)
            except KeyError:
                pass

        #self.print(f'The extended DNS query to {domain} had as answers {answers} ')

        contacted_ips = __database__.get_all_contacted_ips_in_profileid_twid(profileid,twid)
        # If contacted_ips is empty it can be because we didnt read yet all the flows.
        # This is automatically captured later in the for loop and we start a Timer

        # every dns answer is a list of ips that correspond to a spicific query,
        # one of these ips should be present in the contacted ips
        # check each one of the resolutions of this domain
        if answers == ['']:
            # If no IPs are in the answer, we can not expect the computer to connect to anything
            #self.print(f'No ips in the answer, so ignoring')
            return False
        for ip in answers:
            #self.print(f'Checking if we have a connection to ip {ip}')
            if ip in contacted_ips:
                # this dns resolution has a connection. We can exit
                return False

        #self.print(f'It seems that none of the IPs were contacted')
        # Found a DNS query which none of its IPs was contacted
        # It can be that Slips is still reading it from the files. Lets check back in some time
        # Create a timer thread that will wait some seconds for the connection to arrive and then check again
        if uid not in self.connections_checked_in_dns_conn_timer_thread:
            # comes here if we haven't started the timer thread for this dns before
            # mark this dns as checked
            self.connections_checked_in_dns_conn_timer_thread.append(uid)
            params = [ domain, answers, timestamp, profileid, twid, uid]
            #self.print(f'Starting the timer to check on {domain}, uid {uid}. time {datetime.datetime.now()}')
            timer = TimerThread(15, self.check_dns_resolution_without_connection, params)
            timer.start()
        elif uid in self.connections_checked_in_dns_conn_timer_thread:
            #self.print(f'Alerting on {domain}, uid {uid}. time {datetime.datetime.now()}')
            # It means we already checked this dns with the Timer process
            # but still no connection for it.
            for ip in answers:
                if self.check_if_connection_was_made_by_different_version(profileid, twid, ip):
                    return False
            self.helper.set_evidence_DNS_without_conn( domain, timestamp, profileid, twid, uid)
            # This UID will never appear again, so we can remove it and
            # free some memory
            try:
                self.connections_checked_in_dns_conn_timer_thread.remove(uid)
            except ValueError:
                pass
    def check_ssh(self, message):
        """
        Function to check if an SSH connection logged in successfully
        """
        try:
            data = message['data']
            # Convert from json to dict
            data = json.loads(data)
            profileid = data['profileid']
            twid = data['twid']
            # Get flow as a json
            flow = data['flow']
            # Convert flow to a dict
            flow_dict = json.loads(flow)
            timestamp = flow_dict['stime']
            uid = flow_dict['uid']
            # Try Zeek method to detect if SSh was successful or not.
            auth_success = flow_dict['auth_success']
            if auth_success:
                original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                original_flow_uid = next(iter(original_ssh_flow))
                if original_ssh_flow[original_flow_uid]:
                    ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                    daddr = ssh_flow_dict['daddr']
                    saddr = ssh_flow_dict['saddr']
                    size = ssh_flow_dict['allbytes']
                    self.helper.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Zeek')
                    try:
                        self.connections_checked_in_ssh_timer_thread.remove(uid)
                    except ValueError:
                        pass
                    return True
                else:
                    # It can happen that the original SSH flow is not in the DB yet
                    if uid not in self.connections_checked_in_ssh_timer_thread:
                        # comes here if we haven't started the timer thread for this connection before
                        # mark this connection as checked
                        #self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
                        self.connections_checked_in_ssh_timer_thread.append(uid)
                        params = [message]
                        timer = TimerThread(15, self.check_ssh, params)
                        timer.start()
            else:
                # Try Slips method to detect if SSH was successful.
                original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                original_flow_uid = next(iter(original_ssh_flow))
                if original_ssh_flow[original_flow_uid]:
                    ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                    daddr = ssh_flow_dict['daddr']
                    saddr = ssh_flow_dict['saddr']
                    size = ssh_flow_dict['allbytes']
                    if size > self.ssh_succesful_detection_threshold:
                        # Set the evidence because there is no
                        # easier way to show how Slips detected
                        # the successful ssh and not Zeek
                        self.helper.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Slips')
                        try:
                            self.connections_checked_in_ssh_timer_thread.remove(uid)
                        except ValueError:
                            pass
                        return True
                    else:
                        # self.print(f'NO Successsul SSH recived: {data}', 1, 0)
                        pass
                else:
                    # It can happen that the original SSH flow is not in the DB yet
                    if uid not in self.connections_checked_in_ssh_timer_thread:
                        # comes here if we haven't started the timer thread for this connection before
                        # mark this connection as checked
                        #self.print(f'Starting the timer to check on {flow_dict}, uid {uid}. time {datetime.datetime.now()}')
                        self.connections_checked_in_ssh_timer_thread.append(uid)
                        params = [message]
                        timer = TimerThread(15, self.check_ssh, params)
                        timer.start()
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on check_ssh() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)


    def detect_DGA(self, rcode_name, query, stime, profileid, twid, uid):
        """
        Detect DGA based on the amount of NXDOMAINs seen in dns.log
        """

        if not 'NXDOMAIN' in rcode_name or 'in-addr.arpa' in query or query.endswith('.local'):
            return False

        profileid_twid = f'{profileid}_{twid}'

        # found NXDOMAIN by this profile
        try:
            self.nxdomains[profileid_twid] +=1
        except KeyError:
            # first time seeing nxdomain in this profile and tw
            self.nxdomains.update({profileid_twid: 1})
            return False

        # every 10,15,20 .. etc. nxdomains, generate an alert.
        if (self.nxdomains[profileid_twid] % 5 == 0 and
            self.nxdomains[profileid_twid] >= self.nxdomains_threshold):
            self.helper.set_evidence_DGA(self.nxdomains[profileid_twid], stime, profileid, twid, uid)
            return True

    def detect_young_domains(self, domain, stime, profileid, twid, uid):

        age_threshold = 60

        if domain.endswith('.arpa') or domain.endswith('.local'):
            return False

        domain_info = __database__.getDomainData(domain)
        if not domain_info:
            return False

        if 'Age' not in domain_info:
            # we don't have age info about this domain
            return False

        # age is in days
        age = domain_info['Age']
        if age >= age_threshold:
            return False

        self.helper.set_evidence_young_domain(domain, age, stime, profileid, twid, uid)

    def shutdown_gracefully(self):
        __database__.publish('finished_modules', self.name)

    def run(self):
        # Main loop function
        while True:
            try:
                # ---------------------------- new_flow channel
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_flow'):

                    data = message['data']
                    # Convert from json to dict
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    # Get flow as a json
                    flow = data['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)

                    # Convert the common fields to something that can
                    # be interpreted
                    uid = next(iter(flow))
                    flow_dict = json.loads(flow[uid])
                    # Flow type is 'conn' or 'dns', etc.
                    flow_type = flow_dict['flow_type']
                    dur = flow_dict['dur']
                    saddr = flow_dict['saddr']
                    daddr = flow_dict['daddr']
                    origstate = flow_dict['origstate']
                    state = flow_dict['state']
                    timestamp = data['stime']
                    # ports are of type int
                    sport = flow_dict['sport']
                    dport = flow_dict.get('dport', None)
                    proto = flow_dict.get('proto')
                    appproto = flow_dict.get('appproto', '')
                    if not appproto or appproto == '-':
                        appproto = flow_dict.get('type', '')

                    if daddr in self.x:
                        print(f"@@@@@@@@@@@@@ slips detected doh to { daddr}")
                    # stime = flow_dict['ts']
                    # timestamp = data['stime']
                    # pkts = flow_dict['pkts']
                    # allbytes = flow_dict['allbytes']

                    # --- Detect long Connections ---
                    # Do not check the duration of the flow if the daddr or
                    # saddr is multicast.
                    if not ipaddress.ip_address(daddr).is_multicast and not ipaddress.ip_address(saddr).is_multicast:
                        self.check_long_connection(dur, daddr, saddr, profileid, twid, uid, timestamp)

                    # --- Detect unknown destination ports ---
                    if dport:
                        self.check_unknown_port(dport, proto.lower(), daddr, profileid, twid, uid, timestamp)

                    # --- Detect Multiple Reconnection attempts ---
                    key = saddr + '-' + daddr
                    if dport != 0 and origstate == 'REJ':

                        # add this conn to the stored number of reconnections
                        current_reconnections = __database__.getReconnectionsForTW(profileid,twid)
                        current_reconnections[key] = current_reconnections.get(key, 0) + 1
                        __database__.setReconnections(profileid, twid, current_reconnections)

                        if current_reconnections[key] >= 5:
                            description = f"Multiple reconnection attempts to Destination IP: {daddr} " \
                                          f"from IP: {saddr} reconnections: {current_reconnections[key]}"
                            self.helper.set_evidence_for_multiple_reconnection_attempts(profileid, twid,
                                                                                 daddr, description,
                                                                                 uid, timestamp)

                    # --- Detect Connection to port 0 ---
                    if proto not in ('igmp', 'icmp', 'ipv6-icmp') and (sport == 0 or dport == 0):
                        direction = 'source' if sport==0 else 'destination'
                        self.helper.set_evidence_for_port_0_connection(saddr, daddr, direction, profileid, twid, uid, timestamp)

                    # --- Detect if this is a connection without a DNS resolution ---
                    # The exceptions are:
                    # 1- Do not check for DNS requests
                    # 2- Ignore some IPs like private IPs, multicast, and broadcast
                    if flow_type == 'conn' and appproto != 'dns' and not self.is_ignored_ip(daddr):
                        # To avoid false positives in case of an interface don't alert ConnectionWithoutDNS until 30 minutes has passed
                        # after starting slips because the dns may have happened before starting slips
                        start_time = __database__.get_slips_start_time()
                        internal_time = float(__database__.getSlipsInternalTime())
                        internal_time = datetime.datetime.fromtimestamp(internal_time)
                        diff_internal = internal_time - start_time
                        diff_internal = diff_internal.seconds
                        #self.print(f'Start: {start_time}, InternalTime: {internal_time} [diff {diff_internal}]. TH: {self.conn_without_dns_interface_wait_time}')
                        if int(diff_internal) >= self.conn_without_dns_interface_wait_time:
                            self.check_connection_without_dns_resolution(daddr, twid, profileid, timestamp, uid)

                    # --- Detect Connection to multiple ports (for RAT) ---
                    if proto == 'tcp' and state == 'Established':
                        dport_name = appproto
                        if not dport_name:
                            dport_name = __database__.get_port_info(str(dport) + '/' + proto.lower())
                            if dport_name:
                                dport_name = dport_name.upper()
                        # Consider only unknown services
                        else:
                            dport_name = dport_name.upper()
                        # Consider only unknown services
                        if not dport_name:
                            # Connection to multiple ports to the destination IP
                            if profileid.split('_')[1] == saddr:
                                direction = 'Dst'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Client'
                                type_data = 'IPs'
                                dst_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                # make sure we find established connections to this daddr
                                if daddr in dst_IPs_ports:
                                    dstports = list(dst_IPs_ports[daddr]['dstports'])
                                    if len(dstports) > 1:
                                        description = "Connection to multiple ports {} of Destination IP: {}".format(dstports, daddr)
                                        self.helper.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)

                            # Connection to multiple port to the Source IP. Happens in the mode 'all'
                            elif profileid.split('_')[1] == daddr:
                                direction = 'Src'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Server'
                                type_data = 'IPs'
                                src_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                dstports = list(src_IPs_ports[saddr]['dstports'])
                                if len(dstports) > 1:
                                    description = "Connection to multiple ports {} of Source IP: {}".format(dstports, saddr)
                                    self.helper.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)

                    # --- Detect Data exfiltration ---
                    # we’re looking for systems that are transferring large amount of data in 20 mins span
                    all_flows = __database__.get_all_flows_in_profileid(profileid)
                    if all_flows:
                        # get a list of flows without uids
                        flows_list =[]
                        for flow_dict in all_flows:
                            flows_list.append(list(flow_dict.items())[0][1])
                        # sort flows by ts
                        flows_list = sorted(flows_list, key = lambda i: i['ts'])
                        # get first and last flow ts
                        time_of_first_flow = datetime.datetime.fromtimestamp(flows_list[0]['ts'])
                        time_of_last_flow = datetime.datetime.fromtimestamp(flows_list[-1]['ts'])
                        # get the difference between them in seconds

                        diff = str(time_of_last_flow - time_of_first_flow)
                        # if there are days diff between the flows , diff will be something like 1 day, 17:25:57.458395
                        try:
                            # calculate the days difference
                            diff_in_days = int(diff.split(', ')[0].split(' ')[0])
                            diff = diff.split(', ')[1]
                        except (IndexError,ValueError):
                            # no days different
                            diff = diff.split(', ')[0]
                            diff_in_days = 0

                        diff_in_hrs = int(diff.split(':')[0])
                        diff_in_mins = int(diff.split(':')[1])
                        # total diff in mins
                        diff_in_mins = 24*diff_in_days*60 + diff_in_hrs*60 + diff_in_mins

                        # we need the flows that happend in 20 mins span
                        if diff_in_mins >= 20:
                            contacted_daddrs= {}
                            # get a dict of all contacted daddr in the past hour and how many times they were ccontacted
                            for flow in flows_list:
                                daddr = flow['daddr']
                                try:
                                    contacted_daddrs[daddr] = contacted_daddrs[daddr]+1
                                except:
                                    contacted_daddrs.update({daddr: 1})
                            # most of the times the default gateway will be the most contacted daddr, we don't want that
                            # remove it from the dict if it's there
                            contacted_daddrs.pop(self.gateway, None)

                            # get the most contacted daddr in the past hour, if there is any
                            if contacted_daddrs:
                                most_contacted_daddr = max(contacted_daddrs, key=contacted_daddrs.get)
                                times_contacted = contacted_daddrs[most_contacted_daddr]
                                # get the sum of all bytes send to that ip in the past hour
                                total_bytes = 0
                                for flow in flows_list:
                                    daddr = flow['daddr']
                                    # In arp the sbytes is actually ''
                                    if flow['sbytes'] == '':
                                        sbytes = 0
                                    else:
                                        sbytes = flow['sbytes']
                                    if daddr == most_contacted_daddr:
                                        total_bytes = total_bytes + sbytes
                                # print(f'total_bytes:{total_bytes} most_contacted_daddr: {most_contacted_daddr} times_contacted: {times_contacted} ')
                                if total_bytes >= self.data_exfiltration_threshold*(10**6):
                                    # get the first uid of these flows to use for setEvidence
                                    for flow_dict in all_flows:
                                        for uid, flow in flow_dict.items():
                                            if flow['daddr'] == daddr:
                                                break
                                    self.helper.set_evidence_data_exfiltration(most_contacted_daddr, total_bytes, times_contacted, profileid, twid, uid)

                # --- Detect successful SSH connections ---
                message = self.c2.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_ssh'):
                    self.check_ssh(message)

                # --- Detect alerts from Zeek: Self-signed certs, invalid certs, port-scans and address scans, and password guessing ---
                message = self.c3.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_notice'):
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        timestamp = flow['stime']
                        uid = data['uid']
                        msg = flow['msg']
                        note = flow['note']

                        # --- Self signed CERTS ---
                        # We're looking for self signed certs in notice.log in the 'msg' field
                        # The self-signed certs apear in both ssl and notice log. But if we check both
                        # we are going to have repeated evidences. So we only check the ssl log for those
                        """
                        if 'self signed' in msg or 'self-signed' in msg:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            ip_identification = __database__.getIPIdentification(ip)
                            description = f'Self-signed certificate. Destination IP {ip}. {ip_identification}'
                            confidence = 0.5
                            threat_level = 'low'
                            category = "Anomaly.Behaviour"
                            type_detection = 'dstip'
                            type_evidence = 'SelfSignedCertificate'
                            detection_info = ip
                            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                                     threat_level, confidence, description,
                                                     timestamp, category, profileid=profileid,
                                                     twid=twid, uid=uid)
                        """

                        # --- Detect port scans from Zeek logs ---
                        # We're looking for port scans in notice.log in the note field
                        if 'Port_Scan' in note:
                            # Vertical port scan
                            scanning_ip = flow.get('scanning_ip','')
                            self.helper.set_evidence_vertical_portscan(msg, scanning_ip, timestamp, profileid, twid, uid)

                        # --- Detect SSL cert validation failed ---
                        if 'SSL certificate validation failed' in msg \
                                and 'unable to get local issuer certificate' not in msg:
                                ip = flow['daddr']
                                # get the description inside parenthesis
                                ip_identification = __database__.getIPIdentification(ip)
                                description = msg + f' Destination IP: {ip}. {ip_identification}'
                                self.helper.set_evidence_for_invalid_certificates(profileid, twid, ip,
                                                                           description, uid, timestamp)
                                #self.print(description, 3, 0)

                        # --- Detect horizontal portscan by zeek ---
                        if 'Address_Scan' in note:
                            # Horizontal port scan
                            scanned_port = flow.get('scanned_port','')
                            self.helper.set_evidence_horizontal_portscan(msg, scanned_port, timestamp, profileid, twid, uid)
                        # --- Detect password guessing by zeek ---
                        if 'Password_Guessing' in note:
                            self.helper.set_evidence_pw_guessing(msg, timestamp, profileid, twid, uid)

                # --- Detect maliciuos JA3 TLS servers ---
                message = self.c4.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_ssl'):
                    # Check for self signed certificates in new_ssl channel (ssl.log)
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        uid = flow['uid']
                        timestamp = flow['stime']
                        ja3 = flow.get('ja3',False)
                        ja3s = flow.get('ja3s',False)
                        profileid = data['profileid']
                        twid = data['twid']
                        daddr = flow['daddr']
                        saddr = profileid.split('_')[1]

                        if 'self signed' in flow['validation_status']:
                            ip = flow['daddr']
                            ip_identification = __database__.getIPIdentification(ip)
                            server_name = flow.get('server_name') # returns None if not found
                            # if server_name is not None or not empty
                            if not server_name:
                                description = f'Self-signed certificate. Destination IP: {ip}. {ip_identification}'
                            else:
                                description = f'Self-signed certificate. Destination IP: {ip}, SNI: {server_name}. {ip_identification}'
                            self.helper.set_evidence_self_signed_certificates(profileid,twid, ip, description, uid, timestamp)
                            self.print(description, 3, 0)

                        if ja3 or ja3s:

                            # get the dict of malicious ja3 stored in our db
                            malicious_ja3_dict = __database__.get_ja3_in_IoC()

                            if ja3 in malicious_ja3_dict:
                                self.helper.set_evidence_malicious_JA3(malicious_ja3_dict, saddr, profileid, twid, uid, timestamp,  type_='ja3', ioc=ja3)

                            if ja3s in malicious_ja3_dict:
                                self.helper.set_evidence_malicious_JA3(malicious_ja3_dict, daddr, profileid, twid, uid, timestamp, type_='ja3s', ioc=ja3s)

                # --- Learn ports that Zeek knows but Slips doesn't ---
                message = self.c5.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_service'):
                    data = json.loads(message['data'])
                    # uid = data['uid']
                    # profileid = data['profileid']
                    # uid = data['uid']
                    # saddr = data['saddr']
                    port = data['port_num']
                    proto = data['port_proto']
                    service = data['service']
                    port_info = __database__.get_port_info(f'{port}/{proto}')
                    if not port_info and len(service) > 0:
                        # zeek detected a port that we didn't know about
                        # add to known ports
                        __database__.set_port_info(f'{port}/{proto}', service[0])

                # --- Detect DNS issues: 1) DNS resolutions without connection, 2) DGA, 3) young domains, 4) ARPA SCANs ---
                message = self.c6.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = json.loads(message["data"])
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    flow_data = json.loads(data['flow']) # this is a dict {'uid':json flow data}
                    domain = flow_data.get('query', False)
                    answers = flow_data.get('answers', False)
                    rcode_name = flow_data.get('rcode_name', False)
                    stime = data.get('stime', False)

                    # only check dns without connection if we have answers(we're sure the query is resolved)
                    if answers:
                        self.check_dns_resolution_without_connection(domain, answers, stime, profileid, twid, uid)
                    if rcode_name:
                        self.detect_DGA(rcode_name, domain, stime, profileid, twid, uid)
                    if domain:
                        # TODO: not sure how to make sure IP_info is done adding domain age to the db or not
                        self.detect_young_domains(domain, stime, profileid, twid, uid)
                        self.check_dns_arpa_scan(domain, stime, profileid, twid, uid)


                # --- Detect malicious SSL certificates ---
                message = self.c7.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_downloaded_file'):
                    data = json.loads(message['data'])
                    source = data.get('source', '')
                    analyzers = data.get('analyzers', '')
                    sha1 = data.get('sha1', '')
                    if 'SSL' not in source or 'SHA1' not in analyzers:
                        # not an ssl cert
                        continue

                    # check if we have this sha1 marked as malicious from one of our feeds
                    ssl_info_from_db = __database__.get_ssl_info(sha1)
                    if not ssl_info_from_db: continue
                    self.helper.set_evidence_malicious_ssl(data, ssl_info_from_db)

                # --- Detect Bad SMTP logins ---
                message = self.c8.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_smtp'):
                    data = json.loads(message['data'])
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    daddr = data['daddr']
                    saddr = data['saddr']
                    stime = data.get('ts', False)
                    last_reply = data.get('last_reply', False)

                    if 'bad smtp-auth user' in last_reply:
                        try:
                            self.smtp_bruteforce_cache[profileid].append(stime)
                        except KeyError:
                            # first time for this profileid to preform bad smtp login
                            self.smtp_bruteforce_cache.update({
                                profileid: [stime]
                            })
                        self.helper.set_evidence_bad_smtp_login(saddr, daddr, stime, profileid, twid, uid)

                        # check if (3) bad login attemps happened
                        if len(self.smtp_bruteforce_cache[profileid]) == self.smtp_bruteforce_threshold:
                            # check if they happened within 10 seconds or less
                            diff = int(self.smtp_bruteforce_cache[profileid][-1]) - int(self.smtp_bruteforce_cache[profileid][0])
                            if diff <= 10:
                                # remove all 3 logins that caused this alert
                                self.smtp_bruteforce_cache[profileid] = []
                                self.helper.set_evidence_smtp_bruteforce(saddr, daddr, stime,
                                                                         profileid, twid, uid,
                                                                         self.smtp_bruteforce_threshold)
                            else:
                                # remove the first element so we can check the next 3 logins
                                self.smtp_bruteforce_cache[profileid].pop(0)


            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
