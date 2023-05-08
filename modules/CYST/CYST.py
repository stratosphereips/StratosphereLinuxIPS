from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback
import socket
import json
import os
import errno

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'CYST'
    description = 'Communicates with CYST simulation framework'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        self.port = None
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('new_json_evidence')
        self.cyst_UDS = '/tmp/slips.sock'
        # connect to cyst
        self.sock, self.cyst_conn = self.initialize_unix_socket()


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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')



    def initialize_unix_socket(self):
        """
        Slips will be the server, so it has to run before cyst to create the socket
        """
        unix_socket = '/tmp/slips.sock'

        # Make sure the socket does not already exist
        if os.path.exists(unix_socket):
            os.unlink(unix_socket)

        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(unix_socket)


        failure = sock.listen(2)
        if not failure:
            self.print(f"Slips is now listening. waiting for CYST to connect.")
        else:
            self.print(f" failed to initialize sips socket. Error code: {failure}")

        connection, client_address = sock.accept()
        return sock, connection


    def get_flow(self):
        """
        reads 1 flow from the CYST socket and converts it to dict
        returns a dict if the flow was received or False if there was an error
        """
        try:
            self.sock.settimeout(5)
            #todo handle multiple flows received at once i.e. split by \n
            flow: str = self.cyst_conn.recv(10000).decode()
        except ConnectionResetError:
            self.print( 'Connection reset by CYST.', 0, 1)
            return False,
        except socket.timeout:
            self.print('CYST didnt send flows yet.', 0, 1)
            return False

        try:
            flow = json.loads(flow)
        except json.decoder.JSONDecodeError:
            self.print('Invalid json line received from CYST.', 0, 1)
            return False

        return flow

    def send_evidence(self, evidence: str):
        """
        :param evidence: json serialized dict
        """
        # todo test how long will it take slips to respond to cyst
        # todo explicitly sending message length before the message itself.
        self.cyst_conn.sendall(evidence.encode())


    def close_connection(self):
        self.sock.close()

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        return



    def run(self):
        utils.drop_root_privs()

        if not ('-C' in sys.argv or '--CYST' in sys.argv):
            return

        if not hasattr(self, 'sock'):
            # can't connect to cyst. exit module
            return

        while True:
            try:
                # RECEIVE FLOWS FROM CYST
                if flow := self.get_flow():
                    # send the flow to inputprocess so slips can process it normally
                    __database__.publish('new_cyst_flow', json.dumps(flow))


                # SEND EVIDENCE TO CYST
                msg = __database__.get_message(self.c1)
                if msg and msg['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(msg, 'new_json_evidence'):
                    evidence: str = msg['data']
                    self.send_evidence(evidence)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True


