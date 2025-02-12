# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import warnings
import json
from typing import Dict
from uuid import uuid4

import numpy as np
from tensorflow.keras.models import load_model

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Proto,
    Victim,
    Method,
)
from modules.rnn_cc_detection.strato_letters_exporter import (
    StratoLettersExporter,
)

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)


class CCDetection(IModule):
    # Name: short name of the module. Do not use spaces
    name = "RNN C&C Detection"
    description = "Detect C&C channels based on behavioral letters"
    authors = ["Sebastian Garcia", "Kamila Babayeva", "Ondrej Lukas"]

    def init(self):
        self.subscribe_to_channels()
        self.exporter = StratoLettersExporter(self.db)

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_letters")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_letters": self.c1,
            "tw_closed": self.c2,
        }

    def set_evidence_cc_channel(
        self,
        score: float,
        confidence: float,
        uid: str,
        timestamp: str,
        tupleid: str = "",
        profileid: str = "",
        twid: str = "",
    ):
        """
        Set an evidence for malicious Tuple
        :param tupleid: is dash separated daddr-dport-proto
        """
        tupleid = tupleid.split("-")
        dstip, port, proto = tupleid[0], tupleid[1], tupleid[2]
        srcip = profileid.split("_")[-1]
        portproto: str = f"{port}/{proto}"
        port_info: str = self.db.get_port_info(portproto)
        description: str = (
            f"C&C channel, client IP: {srcip} server IP: {dstip} "
            f'port: {port_info.upper() if port_info else ""} {portproto} '
            f'score: {format(score, ".4f")}.'
        )

        timestamp: str = utils.convert_format(timestamp, utils.alerts_format)
        twid_int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            victim=Victim(
                direction=Direction.DST, ioc_type=IoCType.IP, value=dstip
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=timestamp,
            dst_port=int(port),
            proto=Proto(proto.lower()) if proto else None,
            method=Method.AI,
        )
        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.COMMAND_AND_CONTROL_CHANNEL,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=dstip
            ),
            victim=Victim(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=dstip),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
            timestamp=timestamp,
            dst_port=int(port),
            proto=Proto(proto.lower()) if proto else None,
            method=Method.AI,
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
        vocabulary = list("abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*")
        int_of_letters = {}

        # This is a simple encoding that is not one-hot.
        for i, letter in enumerate(vocabulary):
            int_of_letters[letter] = float(i)

        # String to test
        # pre_behavioral_model = "88*y*y*h*h*h*h*h*h*h*y*y*h*h*h*y*y*"

        # Be sure only max_length chars come. Not sure why we receive more
        pre_behavioral_model = pre_behavioral_model[:max_length]

        # Add padding to the letters passed
        # self.print(f'Seq sent: {pre_behavioral_model}')
        pre_behavioral_model += "0" * (max_length - len(pre_behavioral_model))
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

    def get_confidence(self, pre_behavioral_model):
        threshold_confidence = 100
        if len(pre_behavioral_model) >= threshold_confidence:
            return 1

        return len(pre_behavioral_model) / threshold_confidence

    def handle_new_letters(self, msg: Dict):
        """handles msgs from the tw_closed channel"""

        msg = msg["data"]
        msg = json.loads(msg)
        pre_behavioral_model = msg["new_symbol"]
        profileid = msg["profileid"]
        twid = msg["twid"]
        # format of the tupleid is daddr-dport-proto
        tupleid = msg["tupleid"]
        flow = msg["flow"]
        state = flow["state"]

        if "tcp" not in tupleid.lower():
            return

        if "established" not in state.lower():
            return

        # to reduce false positives
        threshold = 0.99
        # function to convert each letter of behavioral model to ascii
        behavioral_model = self.convert_input_for_module(pre_behavioral_model)
        # predict the score of behavioral model being c&c channel
        self.print(
            f"predicting the sequence: {pre_behavioral_model}",
            3,
            0,
        )
        score = self.tcpmodel.predict(behavioral_model, verbose=0)
        self.print(
            f" >> sequence: {pre_behavioral_model}. "
            f"final prediction score: {score[0][0]:.20f}",
            3,
            0,
        )
        # get a float instead of numpy array
        score = score[0][0]
        if score > threshold:
            threshold_confidence = 100
            if len(pre_behavioral_model) >= threshold_confidence:
                confidence = 1
            else:
                confidence = len(pre_behavioral_model) / threshold_confidence
            uid = msg["uid"]
            stime = flow["starttime"]
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
                "attacker_type": utils.detect_ioc_type(flow["daddr"]),
                "profileid": profileid,
                "twid": twid,
                "flow": flow,
            }
            # we only check malicious jarm hashes when there's a CC
            # detection
            self.db.publish("check_jarm_hash", json.dumps(to_send))

    def handle_tw_closed(self, msg: Dict):
        """handles msgs from the tw_closed channel"""
        profileid_tw = msg["data"].split("_")
        profileid = f"{profileid_tw[0]}_{profileid_tw[1]}"
        twid = profileid_tw[-1]
        self.exporter.export(profileid, twid)

    def pre_main(self):
        utils.drop_root_privs()
        # TODO: set the decision threshold in the function call
        try:
            self.tcpmodel = load_model("modules/rnn_cc_detection/rnn_model.h5")
        except AttributeError as e:
            self.print("Error loading the model.")
            self.print(e)
            return 1

        self.exporter.init()

    def main(self):
        if msg := self.get_msg("new_letters"):
            self.handle_new_letters(msg)

        if msg := self.get_msg("tw_closed"):
            self.handle_tw_closed(msg)
