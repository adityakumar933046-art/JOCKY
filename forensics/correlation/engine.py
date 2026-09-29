"""
JOCKY Forensic Correlation Engine.
Coordinates correlation rules, deduplicates relationships deterministically,
discovers cross-system threat connections, and generates correlated threat campaigns.
"""

from typing import Any, Dict, List, Optional, Tuple

from forensics.normalization.models import (
    NormalizedArtifact,
    ArtifactRelationship,
)
from forensics.indicators.models import Indicator
from forensics.correlation.models import CorrelatedFinding, CrossSystemCorrelation
from forensics.correlation.rules import (
    BaseCorrelationRule,
    ProcessNetworkCorrelationRule,
    ProcessFileCorrelationRule,
    ServiceProcessCorrelationRule,
    DriverProcessCorrelationRule,
    PersistenceProcessCorrelationRule,
    CrossSystemCorrelationRule,
)


class CorrelationEngine:
    def __init__(self, rules: Optional[List[BaseCorrelationRule]] = None):
        if rules is not None:
            self.rules = rules
        else:
            self.rules = [
                ProcessNetworkCorrelationRule(),
                ProcessFileCorrelationRule(),
                ServiceProcessCorrelationRule(),
                DriverProcessCorrelationRule(),
                PersistenceProcessCorrelationRule(),
                CrossSystemCorrelationRule(),
            ]

    def register_rule(self, rule: BaseCorrelationRule):
        self.rules.append(rule)

    def run(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: Optional[List[Any]] = None,
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CrossSystemCorrelation], List[CorrelatedFinding]]:
        """
        Run all registered correlation rules against normalized artifacts, extracted indicators,
        and threat findings. Deterministically deduplicates relationships and cross-system correlations.
        """
        findings = findings or []
        all_relationships: Dict[Tuple[str, str, str], ArtifactRelationship] = {}
        all_xcorr: Dict[Tuple[str, str], CrossSystemCorrelation] = {}
        all_correlated_findings: List[CorrelatedFinding] = []

        for rule in self.rules:
            rels, cfnds, xcorrs = rule.correlate(
                artifacts=artifacts,
                indicators=indicators,
                findings=findings,
                organization_id=organization_id,
            )

            # Deduplicate relationships by (source, target, type)
            for r in rels:
                key = (r.source_artifact_id, r.target_artifact_id, r.relationship_type)
                if key not in all_relationships:
                    all_relationships[key] = r
                else:
                    existing = all_relationships[key]
                    existing.evidence_ids = list(set(existing.evidence_ids + r.evidence_ids))
                    existing.confidence = max(existing.confidence, r.confidence)
                    if r.metadata:
                        existing.metadata.update(r.metadata)

            # Deduplicate cross correlations by (type, value)
            for xc in xcorrs:
                xkey = (xc.indicator_type, xc.indicator_value)
                if xkey not in all_xcorr:
                    all_xcorr[xkey] = xc
                else:
                    existing_xc = all_xcorr[xkey]
                    combined_agents = list(set(existing_xc.agent_ids + xc.agent_ids))
                    existing_xc.agent_ids = combined_agents
                    existing_xc.agents_count = len(combined_agents)
                    existing_xc.occurrences += xc.occurrences

            all_correlated_findings.extend(cfnds)

        return (
            list(all_relationships.values()),
            list(all_xcorr.values()),
            all_correlated_findings,
        )


default_correlation_engine = CorrelationEngine()
