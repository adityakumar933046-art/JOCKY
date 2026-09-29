"""
JOCKY Forensic Correlation Models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class CorrelatedFinding:
    """Represents a threat campaign, attack sequence, or multi-indicator correlation."""
    correlation_id: str = field(default_factory=lambda: f"CFND-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    title: str = ""
    category: str = "CORRELATION"
    severity: str = "HIGH"
    confidence: float = 0.85
    description: str = ""
    finding_ids: List[str] = field(default_factory=list)
    artifact_ids: List[str] = field(default_factory=list)
    indicator_ids: List[str] = field(default_factory=list)
    agent_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "organization_id": self.organization_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "finding_ids": self.finding_ids,
            "artifact_ids": self.artifact_ids,
            "indicator_ids": self.indicator_ids,
            "agent_ids": self.agent_ids,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CorrelatedFinding":
        return cls(
            correlation_id=d.get("correlation_id", f"CFND-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            title=d.get("title", ""),
            category=d.get("category", "CORRELATION"),
            severity=d.get("severity", "HIGH"),
            confidence=float(d.get("confidence", 0.85)),
            description=d.get("description", ""),
            finding_ids=d.get("finding_ids", []),
            artifact_ids=d.get("artifact_ids", []),
            indicator_ids=d.get("indicator_ids", []),
            agent_ids=d.get("agent_ids", []),
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class CrossSystemCorrelation:
    """Represents an indicator or behavior observed across multiple distinct endpoints."""
    correlation_id: str = field(default_factory=lambda: f"XCORR-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    indicator_type: str = ""
    indicator_value: str = ""
    agents_count: int = 0
    agent_ids: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    occurrences: int = 0
    severity: str = "HIGH"
    linked_investigation_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "organization_id": self.organization_id,
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "agents_count": self.agents_count,
            "agent_ids": self.agent_ids,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "severity": self.severity,
            "linked_investigation_ids": self.linked_investigation_ids,
            "details": self.details,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CrossSystemCorrelation":
        return cls(
            correlation_id=d.get("correlation_id", f"XCORR-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            indicator_type=d.get("indicator_type", ""),
            indicator_value=d.get("indicator_value", ""),
            agents_count=int(d.get("agents_count", 0)),
            agent_ids=d.get("agent_ids", []),
            first_seen=d.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=d.get("last_seen", datetime.now(timezone.utc).isoformat()),
            occurrences=int(d.get("occurrences", 0)),
            severity=d.get("severity", "HIGH"),
            linked_investigation_ids=d.get("linked_investigation_ids", []),
            details=d.get("details", {}),
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
        )
