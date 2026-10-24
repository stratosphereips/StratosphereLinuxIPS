# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import sys
import contextlib
import warnings
import json
import time
from pathlib import Path
from collections import OrderedDict
from typing import Any, Dict
from uuid import uuid4

import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
from modules.supported_module_names import Modules
from .preprocessing import encode_letters, connection_count, is_established
from slips_files.common.input_type import InputType
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
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


@contextlib.contextmanager
def _silence_native_stderr():
    """Temporarily redirect the C-level stderr (fd 2) to /dev/null.

    TensorFlow prints cuFFT/cuDNN/cuBLAS "already registered" and "computation
    placer already registered" messages straight from its C++ static
    initializers to file descriptor 2, before ``absl::InitializeLog()`` runs.
    Because of that, neither ``TF_CPP_MIN_LOG_LEVEL`` nor the Python logging /
    absl APIs can suppress them. We silence fd 2 only around the TF import and
    model load, then restore it so genuine errors stay visible afterwards.
    """
    sys.stderr.flush()
    saved_stderr_fd = os.dup(2)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull_fd, 2)
        yield
    finally:
        sys.stderr.flush()
        os.dup2(saved_stderr_fd, 2)
        os.close(devnull_fd)
        os.close(saved_stderr_fd)


class CCDetection(IModule):
    # Name: short name of the module. Do not use spaces
    name = Modules.RNN_CC_DETECTION.value
    description = "Detects C&C channels based on behavioral letters"
    authors = ["Sebastian Garcia", "Kamila Babayeva", "Ondrej Lukas"]

    def init(self) -> None:
        """Prepare export and choose the live or accelerated-offline clock."""
        self.offline = (
            self.db.get_input_type() != InputType.INTERFACE
            and not self.args.growing
        )
        self.letters_exporter = StratoLettersExporter(self.db)

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

        timestamp: str = utils.convert_ts_format(
            timestamp, utils.alerts_format
        )
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

    def convert_input_for_module(
        self, pre_behavioral_model: str
    ) -> np.ndarray:
        """Use the same latest-window encoding and padding as training.

        Parameters:
            pre_behavioral_model: Behavioral letter sequence.

        Returns:
            Encoded fixed-size model input.
        """
        return encode_letters(
            pre_behavioral_model, schema=getattr(self, "encoding_schema", 1)
        )

    def handle_new_letters(self, msg: Dict[str, Any]) -> None:
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
        count = connection_count(pre_behavioral_model[-500:])

        if "tcp" not in tupleid.lower():
            return

        if not is_established(state) or count < 6:
            return

        # Keep caches local, bounded and independent of Redis retention.
        if not hasattr(self, "_predictions"):
            self._predictions = OrderedDict()
        key = (profileid, twid, tupleid)
        now = time.monotonic()
        if getattr(self, "offline", False):
            now = float(flow["starttime"])
        previous = self._predictions.get(key)
        progress = int(msg.get("sequence_length", len(pre_behavioral_model)))
        if previous and (progress - previous[0] < 4 or now - previous[1] < 5):
            return
        last_alert = previous[2] if previous else -1e30
        self._predictions[key] = (progress, now, last_alert)
        self._predictions.move_to_end(key)
        if len(self._predictions) > 2048:
            self._predictions.popitem(last=False)
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
        if score > threshold and now - last_alert >= 3600:
            self._predictions[key] = (progress, now, now)
            confidence = min(1.0, count / 100)
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
        profileid_tw = utils.get_msg_payload(msg).split("_")
        profileid = f"{profileid_tw[0]}_{profileid_tw[1]}"
        twid = profileid_tw[-1]
        self.letters_exporter.export(profileid, twid)

    def load_tcp_model(self) -> Any:
        """
        Load the TensorFlow model lazily in the module process.

        TensorFlow is imported here (not at module level) so it is only ever
        initialized inside this module's own process. This avoids the
        "computation placer already registered" warning that occurs when TF is
        imported in the main process and then inherited by forked children.

        Returns:
            Loaded TensorFlow model instance.
        """
        with _silence_native_stderr():
            from tensorflow.keras.models import load_model

            path = Path("modules/rnn_cc_detection/rnn_model.h5")
            metadata = path.with_suffix(path.suffix + ".json")
            self.encoding_schema = (
                json.loads(metadata.read_text())["encoding_schema"]
                if metadata.exists()
                else 1
            )
            if self.encoding_schema not in (1, 2):
                raise ValueError("Unsupported RNN encoding schema")
            if self.encoding_schema == 1:
                self.print(
                    "Legacy C2 model uses ambiguous labels and shares token zero with letter a; retrain with grouped C2 labels before relying on its score.",
                    0,
                    1,
                )
            return load_model(path)

    def pre_main(self):
        utils.drop_root_privs_permanently()
        # TODO: set the decision threshold in the function call
        try:
            self.tcpmodel = self.load_tcp_model()
        except AttributeError as e:
            self.print("Error loading the model.")
            self.print(e)
            return 1

        self.letters_exporter.init()

    def main(self):
        if msg := self.get_msg("new_letters"):
            self.handle_new_letters(msg)

        if msg := self.get_msg("tw_closed"):
            self.handle_tw_closed(msg)
