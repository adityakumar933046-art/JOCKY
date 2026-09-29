"""
JOCKY Base Detection Rule Interface.

Abstract base class for all independent forensic threat detection rules.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity


class DetectionRule(ABC):
    """Base class for all modular JOCKY threat detection rules.
    
    Each rule operates deterministically on structured EvidenceRecord inputs
    and returns zero or more Finding objects. Rules are strictly read-only.
    """

    rule_id: str = "BASE-000"
    name: str = "Base Detection Rule"
    category: str = "GENERAL"
    description: str = "Base rule template"
    severity: Severity = Severity.MEDIUM

    @abstractmethod
    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        """Evaluate rule against a collection of EvidenceRecord instances.
        
        Args:
            evidence: List of evidence records captured by forensic collectors.
            
        Returns:
            List of Finding instances representing detected forensic indicators.
        """
        pass

    def create_finding(
        self,
        title: str,
        description: str,
        affected_object: str,
        hostname: str,
        evidence_ids: List[str],
        indicators: Dict[str, Any],
        recommendation: str,
        severity: Optional[Severity] = None,
        confidence: float = 0.85,
    ) -> Finding:
        """Helper to construct a validated Finding with rule defaults."""
        return Finding(
            rule_id=self.rule_id,
            title=title,
            category=self.category,
            severity=severity or self.severity,
            confidence=confidence,
            description=description,
            hostname=hostname,
            evidence_ids=evidence_ids,
            affected_object=affected_object,
            indicators=indicators,
            recommendation=recommendation,
        )

    @staticmethod
    def filter_evidence_by_operation(evidence: List[EvidenceRecord], operation: str) -> List[EvidenceRecord]:
        """Utility to retrieve evidence records matching a specific operation name."""
        return [rec for rec in evidence if rec.operation == operation]
