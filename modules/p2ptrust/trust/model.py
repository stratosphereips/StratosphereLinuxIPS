# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from modules.p2ptrust.trust.trustdb import TrustDB


class Model:
    """
    Abstract model for computing reputations of peers and IP addresses

    This class defines a method that trust model is expected to have.
    """

    name = "P2P Model"

    def __init__(
        self,
        trustdb: TrustDB,
    ):
        self.trustdb = trustdb

    def get_opinion_on_ip(self, ipaddr: str) -> (float, float, float):
        """
        Compute the network's opinion for a given IP

        :param ipaddr: The IP address for which the opinion is computed
        :return: peer's reputation, score and confidence
        """
        raise NotImplementedError()
