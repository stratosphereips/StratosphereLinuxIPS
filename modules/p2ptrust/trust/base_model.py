# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.printer import Printer
from slips_files.core.output import Output


class BaseModel:
    """
    This class implements a set of methods that get data from the database
    and compute a reputation based on that. Methods
    from this class are requested by the main module process on behalf on
     SLIPS, when SLIPS wants to know the network's
    opinion on peer or IP address.
    This class only uses data that is already inserted in the database. It
    doesn't issue any requests to other peers.
    """

    name = "P2P Base Model"

    def __init__(self, logger: Output, trustdb):
        self.trustdb = trustdb
        self.printer = Printer(logger, self.name)
        self.reliability_weight = 0.7

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_opinion_on_ip(self, ipaddr: str) -> (float, float, float):
        """
        Compute the network's opinion for a given IP

        Reports about the IP and the reporter's credentials are fetched from
        the database. An opinion for that IP is
        computed and cached in the database for later use.

        :param ipaddr: The IP address for which the opinion is computed
        :return: average peer reputation, final score and final confidence
        """

        # get report on that ip that is at most max_age old
        # if no such report is found:

        reports_on_ip = self.trustdb.get_opinion_on_ip(ipaddr)
        if len(reports_on_ip) == 0:
            return None, None
        combined_score, combined_confidence = self.assemble_peer_opinion(
            reports_on_ip
        )

        self.trustdb.update_cached_network_opinion(
            "ip", ipaddr, combined_score, combined_confidence, 0
        )
        return combined_score, combined_confidence

    def compute_peer_trust(
        self, reliability: float, score: float, confidence: float
    ) -> float:
        """
        Compute the opinion value from a peer by multiplying his report data
        and his reputation

        :param reliability: trust value for the peer, obtained from the go
        level
        :param score: score by slips for the peer's IP address
        :param confidence: confidence by slips for the peer's IP address
        :return: The trust we should put in the report given by this peer
        """

        return (
            (reliability * self.reliability_weight) + (score * confidence)
        ) / 2

    def normalize_peer_reputations(self, peers: list) -> (float, float, list):
        """
        Normalize peer reputation

        A list of peer reputations is scaled so that the reputations sum to
         one, while keeping the hierarchy.

        :param peers: a list of peer reputations
        :return: weighted trust value
        """

        # move trust values from [-1, 1] to [0, 1]
        normalized_trust = [(t + 1) / 2 for t in peers]

        normalize_net_trust_sum = sum(normalized_trust)

        weighted_trust = [
            nt / normalize_net_trust_sum for nt in normalized_trust
        ]
        return weighted_trust

    def assemble_peer_opinion(self, data: list) -> (float, float, float):
        """
        Assemble reports given by all peers and compute the overall
        network opinion.

        The opinion is computed by using data from the database, which is a
        list of values: [report_score,
        report_confidence, reporter_reliability, reporter_score,
        reporter_confidence]. The reputation value for a peer
        is computed, then normalized across all peers, and the reports are
         multiplied by this value. The average peer
        reputation, final score and final confidence is returned

        :param data: a list of peers and their reports, in the format given
         by TrustDB.get_opinion_on_ip()
        :return: average peer reputation, final score and final confidence
        """

        reports = []
        reporters = []

        for peer_report in data:
            (
                report_score,
                report_confidence,
                reporter_reliability,
                reporter_score,
                reporter_confidence,
            ) = peer_report
            reports.append((report_score, report_confidence))
            reporters.append(
                self.compute_peer_trust(
                    reporter_reliability, reporter_score, reporter_confidence
                )
            )

        weighted_reporters = self.normalize_peer_reputations(reporters)

        combined_score = sum(
            r[0] * w for r, w, in zip(reports, weighted_reporters)
        )
        combined_confidence = sum(
            [max(0, r[1] * w) for r, w, in zip(reports, reporters)]
        ) / len(reporters)

        return combined_score, combined_confidence
