from dataclasses import dataclass
from typing import List

import numpy as np

from ..model.peer_trust_data import PeerTrustData
from ..model.threat_intelligence import ThreatIntelligence
from ..utils import bound


@dataclass
class PeerReport:
    report_ti: ThreatIntelligence
    """Threat intelligence report."""

    reporter_trust: PeerTrustData
    """How much does Slips trust the reporter."""


class TIAggregation:

    def assemble_peer_opinion(self, data: List[PeerReport]) -> ThreatIntelligence:
        """
        Assemble reports given by all peers and compute the overall network opinion.

        :param data: a list of peers and their reports, in the format given by TrustDB.get_opinion_on_ip()
        :return: final score and final confidence
        """
        raise NotImplemented('')


class AverageConfidenceTIAggregation(TIAggregation):

    def assemble_peer_opinion(self, data: List[PeerReport]) -> ThreatIntelligence:
        """
        Uses average when computing final confidence.
        """
        reports_ti = [d.report_ti for d in data]
        reporters_trust = [d.reporter_trust.service_trust for d in data]

        normalize_net_trust_sum = sum(reporters_trust)
        weighted_reporters = [trust / normalize_net_trust_sum for trust in reporters_trust] \
            if normalize_net_trust_sum > 0 else [0] * len(reporters_trust)

        combined_score = sum(r.score * w for r, w, in zip(reports_ti, weighted_reporters))
        combined_confidence = sum(r.confidence * w for r, w, in zip(reports_ti, reporters_trust)) / len(reporters_trust)

        return ThreatIntelligence(score=combined_score, confidence=combined_confidence)


class WeightedAverageConfidenceTIAggregation(TIAggregation):

    def assemble_peer_opinion(self, data: List[PeerReport]) -> ThreatIntelligence:
        reports_ti = [d.report_ti for d in data]
        reporters_trust = [d.reporter_trust.service_trust for d in data]

        normalize_net_trust_sum = sum(reporters_trust)
        weighted_reporters = [trust / normalize_net_trust_sum for trust in reporters_trust]

        combined_score = sum(r.score * w for r, w, in zip(reports_ti, weighted_reporters))
        combined_confidence = sum(r.confidence * w for r, w, in zip(reports_ti, weighted_reporters))

        return ThreatIntelligence(score=combined_score, confidence=combined_confidence)


class StdevFromScoreTIAggregation(TIAggregation):

    def assemble_peer_opinion(self, data: List[PeerReport]) -> ThreatIntelligence:
        reports_ti = [d.report_ti for d in data]
        reporters_trust = [d.reporter_trust.service_trust for d in data]

        normalize_net_trust_sum = sum(reporters_trust)
        weighted_reporters = [trust / normalize_net_trust_sum for trust in reporters_trust]

        merged_score = [r.score * r.confidence * w for r, w, in zip(reports_ti, weighted_reporters)]
        combined_score = sum(merged_score)
        combined_confidence = bound(1 - np.std(merged_score), 0, 1)

        return ThreatIntelligence(score=combined_score, confidence=combined_confidence)


TIAggregationStrategy = {
    'average': AverageConfidenceTIAggregation,
    'weightedAverage': WeightedAverageConfidenceTIAggregation,
    'stdevFromScore': StdevFromScoreTIAggregation,
}
