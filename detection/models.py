"""
JOCKY Threat Detection Finding and Result Models.

Defines structured data models for forensic indicators, detections, and risk summaries.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid

from detection.severity import Severity


@dataclass
class Finding:
    """A single forensic indicator detected by a detection rule."""
    finding_id: str = field(default_factory=lambda: f"THR-{uuid.uuid4().hex[:6].upper()}")
    rule_id: str = ""
    title: str = ""
    category: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.85
    description: str = ""
    hostname: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_ids: List[str] = field(default_factory=list)
    affected_object: str = ""
    indicators: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into a clean serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "evidence_ids": self.evidence_ids,
            "affected_object": self.affected_object,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = data.get("severity", "MEDIUM")
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        return cls(
            finding_id=data.get("finding_id", f"THR-{uuid.uuid4().hex[:6].upper()}"),
            rule_id=data.get("rule_id", ""),
            title=data.get("title", ""),
            category=data.get("category", ""),
            severity=sev,
            confidence=float(data.get("confidence", 0.85)),
            description=data.get("description", ""),
            hostname=data.get("hostname", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            evidence_ids=data.get("evidence_ids", []),
            affected_object=data.get("affected_object", ""),
            indicators=data.get("indicators", {}),
            recommendation=data.get("recommendation", ""),
        )


@dataclass
class DetectionResult:
    """Consolidated outcome of running the Threat Detection Engine over collected evidence."""
    hostname: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=lambda: {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "total_findings": len(self.findings),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
