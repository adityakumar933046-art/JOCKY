"""
JOCKY Base Correlation Rule.
Defines interface for correlation modules linking artifacts, indicators, and findings.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Tuple

from forensics.normalization.models import NormalizedArtifact, ArtifactRelationship
from forensics.indicators.models import Indicator
from forensics.correlation.models import CorrelatedFinding, CrossSystemCorrelation


class BaseCorrelationRule(ABC):
    rule_id: str = "CORR-BASE"
    name: str = "Base Correlation Rule"
    description: str = ""

    @abstractmethod
    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        pass
