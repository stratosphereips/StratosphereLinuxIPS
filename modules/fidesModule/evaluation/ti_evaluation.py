from collections import defaultdict
from typing import Dict, Tuple, Optional

from ..evaluation.service.interaction import Satisfaction, Weight, SatisfactionLevels
from ..messaging.model import PeerIntelligenceResponse
from ..model.aliases import PeerId, Target
from ..model.peer_trust_data import PeerTrustData, TrustMatrix
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..utils.logger import Logger

logger = Logger(__name__)


class TIEvaluation:
    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        """Evaluate interaction with all peers that gave intelligence responses."""
        raise NotImplemented('Use implementation rather then interface!')

    @staticmethod
    def _weight() -> Weight:
        return Weight.INTELLIGENCE_DATA_REPORT

    @staticmethod
    def _assert_keys(responses: Dict[PeerId, PeerIntelligenceResponse], trust_matrix: TrustMatrix):
        assert trust_matrix.keys() == responses.keys()


class EvenTIEvaluation(TIEvaluation):
    """Basic implementation for the TI evaluation, all responses are evaluated the same.
    This implementation corresponds with Salinity botnet.
    """

    def __init__(self, **kwargs):
        self.__kwargs = kwargs
        self.__satisfaction = kwargs.get('satisfaction', SatisfactionLevels.Ok)

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)

        return {p.peer_id: (p, self.__satisfaction, self._weight()) for p in
                trust_matrix.values()}


class DistanceBasedTIEvaluation(TIEvaluation):
    """Implementation that takes distance from the aggregated result and uses it as a penalisation."""

    def __init__(self, **kwargs):
        self.__kwargs = kwargs

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)
        return self._build_evaluation(
            baseline_score=aggregated_ti.score,
            baseline_confidence=aggregated_ti.confidence,
            responses=responses,
            trust_matrix=trust_matrix
        )

    def _build_evaluation(
            self,
            baseline_score: float,
            baseline_confidence: float,
            responses: Dict[PeerId, PeerIntelligenceResponse],
            trust_matrix: TrustMatrix,
    ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        satisfactions = {
            peer_id: self._satisfaction(
                baseline_score=baseline_score,
                baseline_confidence=baseline_confidence,
                report_score=ti.intelligence.score,
                report_confidence=ti.intelligence.confidence
            )
            for peer_id, ti in responses.items()
        }

        return {p.peer_id: (p, satisfactions[p.peer_id], self._weight()) for p in
                trust_matrix.values()}

    @staticmethod
    def _satisfaction(baseline_score: float,
                      baseline_confidence: float,
                      report_score: float,
                      report_confidence: float) -> Satisfaction:
        return (1 - (abs(baseline_score - report_score) / 2) * report_confidence) * baseline_confidence


class LocalCompareTIEvaluation(DistanceBasedTIEvaluation):
    """This strategy compares received threat intelligence with the threat intelligence from local database.

    Uses the same penalisation system as DistanceBasedTIEvaluation with the difference that as a baseline,
    it does not use aggregated value, but rather local intelligence.

    If it does not find threat intelligence for the target, it falls backs to DistanceBasedTIEvaluation.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__default_ti_getter = kwargs.get('default_ti_getter', None)

    def get_local_ti(self,
                     target: Target,
                     local_ti: Optional[SlipsThreatIntelligence] = None) -> Optional[SlipsThreatIntelligence]:
        if local_ti:
            return local_ti
        elif self.__default_ti_getter:
            return self.__default_ti_getter(target)
        else:
            return None

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 local_ti: Optional[SlipsThreatIntelligence] = None,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)

        ti = self.get_local_ti(aggregated_ti.target, local_ti)
        if not ti:
            ti = aggregated_ti
            logger.warn(f'No local threat intelligence available for target {ti.target}! ' +
                        'Falling back to DistanceBasedTIEvaluation.')

        return self._build_evaluation(
            baseline_score=ti.score,
            baseline_confidence=ti.confidence,
            responses=responses,
            trust_matrix=trust_matrix
        )


class WeighedDistanceToLocalTIEvaluation(TIEvaluation):
    """Strategy combines DistanceBasedTIEvaluation and LocalCompareTIEvaluation with the local weight parameter."""

    def __init__(self, **kwargs):
        super().__init__()
        self.__distance = kwargs.get('distance', DistanceBasedTIEvaluation())
        self.__local = kwargs.get('localDistance', LocalCompareTIEvaluation())
        self.__local_weight = kwargs.get('localWeight', 0.5)

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)

        distance_data = self.__distance.evaluate(aggregated_ti, responses, trust_matrix, **kwargs)
        local_data = self.__local.evaluate(aggregated_ti, responses, trust_matrix, **kwargs)

        return {p.peer_id: (p,
                            self.__local_weight * local_data[p.peer_id][1] +
                            (1 - self.__local_weight) * distance_data[p.peer_id][1],
                            self._weight()
                            ) for p in trust_matrix.values()}


class MaxConfidenceTIEvaluation(TIEvaluation):
    """Strategy combines DistanceBasedTIEvaluation, LocalCompareTIEvaluation and EvenTIEvaluation
    in order to achieve maximal confidence when producing decision.
    """

    def __init__(self, **kwargs):
        super().__init__()
        self.__distance = kwargs.get('distance', DistanceBasedTIEvaluation())
        self.__local = kwargs.get('localDistance', LocalCompareTIEvaluation())
        self.__even = kwargs.get('even', EvenTIEvaluation())

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)
        zero_dict = defaultdict(lambda: (None, 0, None))

        # weight of the distance based evaluation
        distance_weight = aggregated_ti.confidence
        distance_data = self.__distance.evaluate(aggregated_ti, responses, trust_matrix, **kwargs) \
            if distance_weight > 0 \
            else zero_dict

        # now we need to check if we even have some threat intelligence data
        local_ti = self.__local.get_local_ti(aggregated_ti.target, **kwargs)
        # weight of the local evaluation
        local_weight = min(1 - distance_weight, local_ti.confidence) if local_ti else 0
        local_data = self.__local.evaluate(aggregated_ti, responses, trust_matrix, **kwargs) \
            if local_weight > 0 \
            else zero_dict

        # weight of the same eval
        even_weight = 1 - distance_weight - local_weight
        even_data = self.__even.evaluate(aggregated_ti, responses, trust_matrix, **kwargs) \
            if even_weight > 0 \
            else zero_dict

        def aggregate(peer: PeerId):
            return distance_weight * distance_data[peer][1] + \
                   local_weight * local_data[peer][1] + \
                   even_weight * even_data[peer][1]

        return {p.peer_id: (p, aggregate(p.peer_id), self._weight()) for p in
                trust_matrix.values()}


class ThresholdTIEvaluation(TIEvaluation):
    """Employs DistanceBasedTIEvaluation when the confidence of the decision
    is higher than given threshold. Otherwise, it uses even evaluation.
    """

    def __init__(self, **kwargs):
        self.__kwargs = kwargs
        self.__threshold = kwargs.get('threshold', 0.5)
        self.__lower = kwargs.get('lower', EvenTIEvaluation())
        self.__higher = kwargs.get('higher', DistanceBasedTIEvaluation())

    def evaluate(self,
                 aggregated_ti: SlipsThreatIntelligence,
                 responses: Dict[PeerId, PeerIntelligenceResponse],
                 trust_matrix: TrustMatrix,
                 **kwargs,
                 ) -> Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]:
        super()._assert_keys(responses, trust_matrix)

        return self.__higher.evaluate(aggregated_ti, responses, trust_matrix) \
            if self.__threshold <= aggregated_ti.confidence \
            else self.__lower.evaluate(aggregated_ti, responses, trust_matrix)


EvaluationStrategy = {
    'even': EvenTIEvaluation,
    'distance': DistanceBasedTIEvaluation,
    'localDistance': LocalCompareTIEvaluation,
    'threshold': ThresholdTIEvaluation,
    'maxConfidence': MaxConfidenceTIEvaluation,
    'weighedDistance': WeighedDistanceToLocalTIEvaluation
}
