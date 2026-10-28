# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing_extensions import List
from typing import Callable
import time

from slips_files.common.printer import Printer
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output
from modules.p2p_trust.trust.report_validation import (
    MATCH_WINDOW,
    LOCAL_REPUTATION_HALF_LIFE,
    MAX_CREDIT,
    ReportValidator,
)

RELIABILITY_WEIGHT = 0.7


def local_maliciousness_to_thesis_score(maliciousness: float) -> float:
    """Express a local Slips threat score using the thesis's peer scale.

    Parameters:
        maliciousness: Slips score, from 0 (no detected threat) to 1.

    Returns:
        Peer-behavior score, from 1 (benign) to -1 (malicious).
    """
    return 1 - 2 * maliciousness


def peer_trust_details(
    reliability: float,
    score: float | None,
    confidence: float | None,
    reliability_weight: float = RELIABILITY_WEIGHT,
    agreement_credit: float = 0.0,
) -> dict[str, float | bool | None]:
    """Calculate thesis trust and expose the contribution of each input.

    Parameters:
        reliability: Locally measured communication reliability, from 0 to 1.
        score: Local maliciousness, from 0 to 1; None means unknown.
        confidence: Confidence in the local assessment; None means unknown.
        reliability_weight: Weight limiting communication's influence.
        agreement_credit: Reward earned from distinct locally corroborated targets.

    Returns:
        Trust, its communication/local contributions and assessment inputs.
    """
    assessed = score is not None and confidence is not None and confidence > 0
    local = (
        local_maliciousness_to_thesis_score(score) * confidence
        if assessed
        else 0.0
    )
    communication = reliability * reliability_weight
    base = (communication + local) / 2
    learned = min(MAX_CREDIT, max(0.0, agreement_credit))
    if assessed and score >= 0.8 and confidence >= 0.8:
        learned = 0.0
    return {
        "trust": max(-0.5, min(0.85, base + learned)),
        "base_trust": base,
        "agreement": learned,
        "communication": communication / 2,
        "local_behavior": local / 2,
        "local_assessed": assessed,
        "local_maliciousness": score if assessed else None,
        "local_confidence": confidence if assessed else 0.0,
        "communication_limit": reliability_weight / 2,
    }


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

    name = "p2p_base_model"

    def __init__(
        self,
        logger: Output,
        trustdb,
        main_slips_db: DBManager,
        report_validation: ReportValidator | None = None,
        network_identity: Callable[[], str] | None = None,
        local_reputation_half_life: float = LOCAL_REPUTATION_HALF_LIFE,
    ):
        self.trustdb = trustdb
        self.main_slips_db = main_slips_db
        self.printer = Printer(logger, self.name)
        self.reliability_weight = RELIABILITY_WEIGHT
        self.report_validation = report_validation
        self.network_identity = network_identity
        self.local_reputation_half_life = local_reputation_half_life
        self.last_corroboration = {"target": "", "support": 0, "peers": []}

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_opinion_on_ip(
        self, ipaddr: str, after_id: int | None = None
    ) -> tuple[float | None, float | None]:
        """
        Compute the network's opinion for a given IP

        Reports about the IP and the reporter's credentials are fetched from
        the database. An opinion for that IP is
        computed and cached in the database for later use.

        :param ipaddr: The IP address for which the opinion is computed
        :param after_id: Restrict reports to replies received for this lookup
        :return: average peer reputation, final score and final confidence
        """

        if getattr(self, "report_validation", None) is not None:
            opinion = self._validated_opinion(ipaddr, after_id)
            if opinion[0] is not None:
                self.trustdb.update_cached_network_opinion(
                    "ip", ipaddr, *opinion, 0
                )
            return opinion

        # get report on that ip that is at most max_age old
        # if no such report is found:
        # reports_on_ip looks like this:
        # [(report_score, report_confidence, reporter_reliability,
        # reporter_score, reporter_confidence, reporter_ipaddress), ...]
        reports_on_ip: List[tuple] = (
            self.trustdb.get_opinion_on_ip(ipaddr, after_id)
            if after_id is not None
            else self.trustdb.get_opinion_on_ip(ipaddr)
        )
        if len(reports_on_ip) == 0:
            return None, None
        combined_score, combined_confidence = self.assemble_peer_opinion(
            reports_on_ip
        )

        self.trustdb.update_cached_network_opinion(
            "ip", ipaddr, combined_score, combined_confidence, 0
        )
        return combined_score, combined_confidence

    def _validated_opinion(
        self, ipaddr: str, after_id: int | None
    ) -> tuple[float | None, float | None]:
        """Group shared detector dependencies and apply reviewed report accuracy.

        Parameters:
            ipaddr: Reported host.
            after_id: Fresh-reply boundary for the current lookup.

        Returns:
            Network score and confidence; corroboration is retained separately.
        """
        target = f"{self.network_identity()}|{ipaddr}"
        reports = self.report_validation.reports_for_target(target)
        families = {}
        reviewed_families = set()
        contributions = []
        weights = {}
        agreement_credits = {}
        for report in reports:
            if (
                after_id is not None
                and report.get("raw_report_id", 0) <= after_id
            ):
                continue
            peer = report["peer_id"]
            _seen, reporter_ip = self.trustdb.get_ip_of_peer(peer)
            reliability = self.trustdb.get_reporter_reliability(peer)
            if not reporter_ip or reporter_ip == ipaddr or reliability is None:
                continue
            local_score, local_confidence, _ = (
                self.report_validation.local_report(
                    f"{self.network_identity()}|{reporter_ip}",
                    max_age=None,
                    decay_half_life=self.local_reputation_half_life,
                )
            )
            if local_score is None or local_confidence is None:
                local_score, local_confidence = 0.5, 0.0
            if peer not in agreement_credits:
                agreement_credits[peer] = (
                    self.report_validation.peer_agreement(peer)["adjustment"]
                )
            agreement_credit = agreement_credits[peer]
            trust = self.compute_peer_trust(
                reliability,
                local_score,
                local_confidence,
                agreement_credit=agreement_credit,
            )
            detector = report["detector"]
            kind, version = detector["evidence_type"], detector["rule_version"]
            feedback = self.report_validation.report_adjustment(
                peer, kind, version
            )
            bonus = min(MAX_CREDIT - agreement_credit, feedback["adjustment"])
            if local_score >= 0.8 and local_confidence >= 0.8:
                bonus = min(0, bonus)
            trust = max(-0.5, min(0.85, trust + bonus))
            cohort = (kind, version, report["network_id"])
            if cohort not in weights:
                weights[cohort] = self.report_validation.detector_weight(
                    kind, version, report["network_id"] + "|"
                )
            confidence = report["confidence"] * weights[cohort]
            verdict = self.report_validation.report_verdict(report)
            if verdict == "true_positive":
                reviewed_families.add(detector["family"])
            if verdict in {
                "false_positive",
                "conflict",
            }:
                confidence = 0
            family = detector["family"]
            # One reporter contributes once within a shared dependency family.
            previous = families.setdefault(family, {}).get(peer)
            opinion = (report["score"], confidence, trust)
            if previous is None or confidence > previous[1]:
                families[family][peer] = opinion
            if (
                kind != "legacy"
                and report.get("blame_at", 0) >= time.time() - MATCH_WINDOW
            ):
                contributions.append(
                    (
                        max(0, trust) * confidence * report["score"],
                        peer,
                        family,
                    )
                )
            self.main_slips_db.set_peer_trust(
                reporter_ip,
                self.compute_peer_trust(
                    reliability, local_score, local_confidence
                ),
            )
        # Correlated reports stay one unit; independent units also need distinct IDs.
        chosen_peers, chosen_families = set(), set()
        support = 0.0
        for value, peer, family in sorted(contributions, reverse=True):
            if (
                peer not in chosen_peers
                and family not in chosen_families
                and family != "unknown"
            ):
                support += value
                chosen_peers.add(peer)
                chosen_families.add(family)
        self.last_corroboration = {
            "target": target,
            "support": support,
            "peers": sorted(chosen_peers),
        }
        units = []
        family_opinions = {}
        for family, family_reports in families.items():
            values = list(family_reports.values())
            total = sum((trust + 1) / 2 for _, _, trust in values)
            score = (
                sum(score * (trust + 1) / 2 for score, _, trust in values)
                / total
            )
            confidence = sum(
                max(0, trust * confidence) for _, confidence, trust in values
            ) / len(values)
            units.append((score, confidence))
            family_opinions[family] = {
                "score": score,
                "confidence": confidence,
                "validated": family in reviewed_families,
            }
        self.last_corroboration["families"] = family_opinions
        if not units:
            return None, None
        return (
            sum(score for score, _ in units) / len(units),
            sum(confidence for _, confidence in units) / len(units),
        )

    def compute_peer_trust(
        self,
        reliability: float,
        score: float,
        confidence: float,
        agreement_credit: float = 0.0,
    ) -> float:
        """Compute base peer trust using thesis equation 3.1.

        Parameters:
            reliability: Communication reliability measured by Pigeon.
            score: Local maliciousness of the reporter's IP, from 0 to 1.
            confidence: Confidence in that local assessment, from 0 to 1.
            agreement_credit: Peer-wide reward for distinct corroborated targets.

        Returns:
            Learned peer trust before detector-specific review adjustments.
        """
        return peer_trust_details(
            reliability,
            score,
            confidence,
            self.reliability_weight,
            agreement_credit,
        )["trust"]

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
         (
            report_score,
            report_confidence,
            reporter_reliability,
            reporter_score, # what does slips think about the reporter's ip
            # how confident slips is about the reporter's ip's score
            reporter_confidence,
            reporter_ipaddress,
        )
        :return: average peer reputation, final score and final confidence
        """
        report_groups = []

        for peer_report in data:
            if len(peer_report) == 6:
                (
                    report_score_sum,
                    report_confidence_sum,
                    reporter_reliability,
                    reporter_score,
                    reporter_confidence,
                    reporter_ipaddress,
                ) = peer_report
                report_count = 1
            else:
                (
                    report_score_sum,
                    report_confidence_sum,
                    reporter_reliability,
                    reporter_score,
                    reporter_confidence,
                    reporter_ipaddress,
                    report_count,
                ) = peer_report

            peer_trust = self.compute_peer_trust(
                reporter_reliability, reporter_score, reporter_confidence
            )
            report_groups.append(
                (
                    report_score_sum,
                    report_confidence_sum,
                    peer_trust,
                    report_count,
                )
            )
            self.main_slips_db.set_peer_trust(reporter_ipaddress, peer_trust)

        normalized_trust_sum = sum(
            ((peer_trust + 1) / 2) * count
            for _, _, peer_trust, count in report_groups
        )
        combined_score = sum(
            report_score_sum * ((peer_trust + 1) / 2) / normalized_trust_sum
            for report_score_sum, _, peer_trust, _ in report_groups
        )
        combined_confidence = sum(
            max(0, report_confidence_sum * peer_trust)
            for _, report_confidence_sum, peer_trust, _ in report_groups
        ) / sum(count for _, _, _, count in report_groups)

        # to ensure the score and confidence are within the range [0, 1]
        # this avoids python issues with negative values or values
        # slightly above 1.0
        combined_score = min(1.0, max(0.0, combined_score))
        combined_confidence = min(1.0, max(0.0, combined_confidence))

        return combined_score, combined_confidence
