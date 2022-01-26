# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
from ..CESNET.warden_client import Client, read_cfg, Error, format_timestamp
import os
import json
import time
import threading
import queue
import ipaddress
import validators

class Module(Module, multiprocessing.Process):
    name = 'CESNET'
    description = 'Send and receive alerts from warden servers.'
    authors = ['Alya Gomaa']

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
        self.read_configuration()
        self.c1 = __database__.subscribe('new_alert')
        self.timeout = 0.0000001
        self.stop_module = False

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

    def read_configuration(self):
        """ Read importing/exporting preferences from slips.conf """

        self.send_to_warden = self.config.get('CESNET', 'send_alerts').lower()

        self.receive_from_warden = self.config.get('CESNET', 'receive_alerts').lower()
        if 'yes' in self.receive_from_warden:
            # how often should we get alerts from the server?
            try:
                self.poll_delay = int(self.config.get('CESNET', 'receive_delay'))
            except ValueError:
                # By default push every 1 day
                self.poll_delay = 86400

        self.configuration_file = self.config.get('CESNET', 'configuration_file')
        if not os.path.exists(self.configuration_file):
            self.print(f"Can't find warden.conf at {self.configuration_file}. Stopping module.")
            self.stop_module = True


    def export_evidence(self, wclient, alert_ID):
        """
        Exports all evidence causing the given alert to warden server
        :param alert_ID: alert to export to warden server
        """
        # get all the evidence causing this alert
        evidence_IDs:list = __database__.get_evidence_causing_alert(alert_ID)
        if not evidence_IDs:
            # something went wrong while getting the list of evidence
            return False

        profile, ip, twid, ID = alert_ID.split('_')
        profileid = f'{profile}_{ip}'

        # this will contain alerts in IDEA format ready to be exported
        alerts_to_export = []
        for ID in evidence_IDs:
            evidence = __database__.get_evidence_by_ID(profileid, twid, ID)
            srcip = profileid.split('_')[1]
            type_evidence = evidence.get('type_evidence')
            detection_info = evidence.get('detection_info')
            # don't send private IPv4 or IPv6 addresses
            if (validators.ipv4(detection_info)
                    and ipaddress.IPv4Address(detection_info).is_private)\
                or (validators.ipv6(detection_info)
                        and ipaddress.IPv6Address(detection_info).is_private):
                continue
            type_detection = evidence.get('type_detection')
            description = evidence.get('description')
            confidence = evidence.get('confidence')
            category = evidence.get('category')
            conn_count = evidence.get('conn_count')
            source_target_tag = evidence.get('source_target_tag')
            port = evidence.get('port')
            proto = evidence.get('proto')

            evidence_in_IDEA = utils.IDEA_format(srcip, type_evidence, type_detection,
                    detection_info, description,
                    confidence, category, conn_count,
                    source_target_tag, port, proto)

            # add Node info to the alert
            evidence_in_IDEA.update({"Node": self.node_info})
            # Add test to the categories because we're still in probation mode
            evidence_in_IDEA['Category'].append('Test')
            evidence_in_IDEA.update({"Category": evidence_in_IDEA["Category"]})
            alerts_to_export.append(evidence_in_IDEA)

        # [2] Upload to warden server
        self.print(f"Uploading {len(alerts_to_export)} events to warden server.")
        # create a thread for sending alerts to warden server
        # and don't stop this module until the thread is done
        q = queue.Queue()
        self.sender_thread = threading.Thread(target=wclient.sendEvents, args=[alerts_to_export, q])
        self.sender_thread.start()
        self.sender_thread.join()
        result = q.get()

        try:
            if 'saved' in result:
                # no errors
                self.print(f'Done uploading {result["saved"]} events to warden server.\n')
        except TypeError:
            # print the error
            self.print(result, 0, 1)


    def import_alerts(self, wclient):
        events_to_get = 10

        cat = ['Availability', 'Abusive.Spam','Attempt.Login', 'Attempt', 'Information',
         'Fraud.Scam', 'Information', 'Fraud.Scam']

        # cat = ['Abusive.Spam']
        nocat = []

        #tag = ['Log', 'Data','Flow', 'Datagram']
        tag = []
        notag = []

        #group = ['cz.tul.ward.kippo','cz.vsb.buldog.kippo', 'cz.zcu.civ.afrodita','cz.vutbr.net.bee.hpscan']
        group = []
        nogroup = []

        self.print(f"Getting {events_to_get} events from warden server.")
        events = wclient.getEvents(count=events_to_get, cat=cat, nocat=nocat,
                                tag=tag, notag=notag, group=group,
                                nogroup=nogroup)

        if len(events) == 0:
            self.print(f'Error getting event from warden server.')
            return False

        # now that we received from warden server,
        # store the received IPs, description, category and node in the db
        src_ips = {} #todo is the srcip always the offender? can it be the victim?
        for event in events:
            # extract event details
            srcips = event.get('Source',[])
            description = event.get('Description','')
            category = event.get('Category',[])

            # get the source of this IoC
            node = event.get('Node',[{}])
            # node is an array of dicts
            if node == []:
                # we don't know the source of this info, skip it
                continue
            # use the node that has a software name defined
            node_name = node[0].get('Name','')
            software = node[0].get('SW',[False])[0]
            if not software:
                # first node doesn't have a software
                # use the second one
                try:
                    node_name = node[1].get('Name','')
                    software = node[1].get('SW',[None])[0]
                except IndexError:
                    # there's no second node
                    pass

            # sometimes one alert can have multiple srcips
            for srcip in srcips:
                # store the event info in a form recognizable by slips
                event_info = {
                    'description': description,
                    'source': f'{node_name}, software: {software}',
                    'threat_level': 'medium',
                    'tags': category[0]
                }
                # srcip is a dict, for example

                # IoC can be ipv6 ar v4
                if 'IP4' in srcip:
                    srcip = srcip['IP4'][0]
                elif 'IP6' in srcip:
                    srcip = srcip['IP6'][0]
                else:
                    srcip = srcip['IP'][0]

                src_ips.update({
                    srcip: json.dumps(event_info)
                })

        __database__.add_ips_to_IoC(src_ips)

    def run(self):
        # Stop module if the configuration file is invalid or not found
        if self.stop_module:
            return False
        # create the warden client
        wclient = Client(**read_cfg(self.configuration_file))

        # All methods return something.
        # If you want to catch possible errors (for example implement some
        # form of persistent retry, or save failed events for later, you may
        # check for Error instance and act based on contained info.
        # If you want just to be informed, this is not necessary, just
        # configure logging correctly and check logs.

        # for getting send and receive limits
        # info = wclient.getInfo()
        # self.print(info, 0, 1)

        self.node_info = [{
            "Name": wclient.name,
            "Type": ["IPS"],
            "SW": ['Slips']
        }]

        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if 'yes' in self.receive_from_warden:
                    last_update = __database__.get_last_warden_poll_time()
                    now = time.time()
                    # did we wait the poll_delay period since last poll?
                    if last_update + self.poll_delay < now:
                        self.import_alerts(wclient)
                        # set last poll time to now
                        __database__.set_last_warden_poll_time(now)

                # in case of an interface or a file, push every time we get an alert
                if (utils.is_msg_intended_for(message, 'new_alert')
                        and 'yes' in self.send_to_warden):
                    alert_ID = message['data']
                    self.export_evidence(wclient, alert_ID)



            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            # except Exception as inst:
            #     exception_line = sys.exc_info()[2].tb_lineno
            #     self.print(f'Problem on the run() line {exception_line}', 0, 1)
            #     self.print(str(type(inst)), 0, 1)
            #     self.print(str(inst.args), 0, 1)
            #     self.print(str(inst), 0, 1)
            #     return True
            # 
            # 

