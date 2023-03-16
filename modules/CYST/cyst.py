
# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback
import socket


class CYST():
    # Name: short name of the module. Do not use spaces
    name = 'CYST'
    description = 'module with functions that setup a unix domain socket to communicate with CYST simulation framework'
    authors = ['Alya Gomaa']

    def __init__(self):
        self.cyst_UDS = '/tmp/slips'

    def connect(self) -> tuple:
        """
        Connects to CYST's UDS
        returns True, '' if the connection was successfull
        and Tuple(False, error_msg) if there was an error

        """
        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        #todo cyst has to start before slips to init the socket
        try:
            sock.connect(self.cyst_UDS)
        except (socket.error) as msg:
            error = f"Problem connecting to CYST socket: {msg}"
            return False, error

        self.sock = sock
        return True ,''

    def get_flow(self) -> tuple:
        """
        reads 1 flow from the CYST socket and converts it to dict
        returns True, flow_dict if the flow was received
        and Tuple(False, Error_msg) if there was an error
        """
        flow: str = self.sock.recv(10000).decode()
        try:
            flow = json.loads(flow)
        except json.decoder.JSONDecodeError:
            msg = f'Invalid json line received from CYST.'
            return False, msg

        return flow, ''

    def send_evidence(self, evidence: str):
        """
        :param evidence: json serialized dict
        """
        # todo test how long will it take slips to respond to cyst
        self.sock.sendall(evidence.encode())



    def close_connection(self):
        self.sock.close()

cyst = CYST()

