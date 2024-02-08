# Must imports
import warnings
import json
import numpy as np
from typing import Optional
from tensorflow.python.keras.models import load_model

from slips_files.common.imports import *
from slips_files.core.evidence_structure.evidence import \
    (
        Evidence,
        ProfileID,
        TimeWindow,
        Attacker,
        ThreatLevel,
        EvidenceType,
        IoCType,
        Direction,
        IDEACategory,
        Victim,
        Proto,
        Tag
    )


warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)


class CCDetection(IModule):
    # Name: short name of the module. Do not use spaces
    name = 'RNN C&C Detection'
    description = 'Detect C&C channels based on behavioral letters'
    authors = ['Sebastian Garcia', 'Kamila Babayeva', 'Ondrej Lukas']

    def init(self):
        self.c1 = self.db.subscribe('new_letters')
        self.channels = {
            'new_letters': self.c1,
        }


    def set_evidence_cc_channel(
        self,
        score: float,
        confidence: float,
        uid: str,
        timestamp: str,
        tupleid: str = '',
        profileid: str = '',
        twid: str = '',
    ):
        """
        Set an evidence for malicious Tuple
        """
        tupleid = tupleid.split('-')
        dstip, port, proto = tupleid[0], tupleid[1], tupleid[2]
        srcip = profileid.split("_")[-1]

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=srcip
            )

        threat_level: ThreatLevel = ThreatLevel.HIGH
        portproto: str = f'{port}/{proto}'
        port_info: str = self.db.get_port_info(portproto)
        ip_identification: str = self.db.get_ip_identification(dstip)
        description: str = (
            f'C&C channel, destination IP: {dstip} '
            f'port: {port_info.upper() if port_info else ""} {portproto} '
            f'score: {format(score, ".4f")}. {ip_identification}'
        )

        timestamp: str = utils.convert_format(timestamp, utils.alerts_format)
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.INTRUSION_BOTNET,
            source_target_tag=Tag.BOTNET,
            port=int(port),
            proto=Proto(proto.lower()) if proto else None,
        )

        self.db.set_evidence(evidence)


    def convert_input_for_module(self, pre_behavioral_model):
        """
        Takes the input from the letters and converts them
        to whatever is needed by the model
        The pre_behavioral_model is a 1D array of letters in an array
        """
        # TODO: set the max_length in the function call

        # Length of behavioral model with which we trained our module
        max_length = 500

        # Convert each of the stratosphere letters to an integer. There are 50
        vocabulary = list('abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*')
        int_of_letters = {}
        for i, letter in enumerate(vocabulary):
            int_of_letters[letter] = float(i)

        # String to test
        # pre_behavioral_model = "88*y*y*h*h*h*h*h*h*h*y*y*h*h*h*y*y*"

        # Be sure only max_length chars come. Not sure why we receive more
        pre_behavioral_model = pre_behavioral_model[:max_length]

        # Add padding to the letters passed
        # self.print(f'Seq sent: {pre_behavioral_model}')
        pre_behavioral_model += '0' * (max_length - len(pre_behavioral_model))
        # self.print(f'Padded Seq sent: {pre_behavioral_model}')

        # Convert to ndarray
        pre_behavioral_model = np.array(
            [[int_of_letters[i]] for i in pre_behavioral_model]
        )
        # self.print(f'The sequence has shape {pre_behavioral_model.shape}')

        # Reshape into (1, 500, 1) We need the first 1, because this is one sample only, but keras expects a 3d vector
        pre_behavioral_model = np.reshape(
            pre_behavioral_model, (1, max_length, 1)
        )

        # self.print(f'Post Padded Seq sent: {pre_behavioral_model}. Shape: {pre_behavioral_model.shape}')
        return pre_behavioral_model

    def pre_main(self):
        utils.drop_root_privs()
        # TODO: set the decision threshold in the function call
        try:
            # Download lstm model
            self.tcpmodel = load_model('modules/rnn_cc_detection/rnn_model.h5')
        except AttributeError as e:
            self.print('Error loading the model.')
            self.print(e)
            return 1

    def main(self):
        # Main loop function
        if msg:= self.get_msg('new_letters'):
            msg = msg['data']
            msg = json.loads(msg)
            pre_behavioral_model = msg['new_symbol']
            profileid = msg['profileid']
            twid = msg['twid']
            tupleid = msg['tupleid']
            flow = msg['flow']

            if 'tcp' in tupleid.lower():
                # to reduce false positives
                threshold = 0.99
                # function to convert each letter of behavioral model to ascii
                behavioral_model = self.convert_input_for_module(
                    pre_behavioral_model
                )
                # predict the score of behavioral model being c&c channel
                self.print(
                    f'predicting the sequence: {pre_behavioral_model}', 3, 0,
                )
                score = self.tcpmodel.predict(behavioral_model)
                self.print(
                    f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 3, 0,
                )
                # get a float instead of numpy array
                score = score[0][0]
                if score > threshold:
                    threshold_confidence = 100
                    if (
                        len(pre_behavioral_model)
                        >= threshold_confidence
                    ):
                        confidence = 1
                    else:
                        confidence = (
                            len(pre_behavioral_model)
                            / threshold_confidence
                        )
                    uid = msg['uid']
                    stime = flow['starttime']
                    self.set_evidence_cc_channel(
                        score,
                        confidence,
                        uid,
                        stime,
                        tupleid,
                        profileid,
                        twid,
                    )
                    to_send = {
                        'attacker_type': utils.detect_data_type(flow['daddr']),
                        'profileid' : profileid,
                        'twid' : twid,
                        'flow': flow,
                    }
                    # we only check malicious jarm hashes when there's a CC
                    # detection
                    self.db.publish('check_jarm_hash', json.dumps(to_send))

            """
            elif 'udp' in tupleid.lower():
                # Define why this threshold
                threshold = 0.7
                # function to convert each letter of behavioral model to ascii
                behavioral_model = self.convert_input_for_module(pre_behavioral_model)
                # predict the score of behavioral model being c&c channel
                self.print(f'predicting the sequence: {pre_behavioral_model}', 4, 0)
                score = udpmodel.predict(behavioral_model)
                self.print(f' >> sequence: {pre_behavioral_model}. final prediction score: {score[0][0]:.20f}', 5, 0)
                # get a float instead of numpy array
                score = score[0][0]
                if score > threshold:
                    self.set_evidence(score, tupleid, profileid, twid)
            """
