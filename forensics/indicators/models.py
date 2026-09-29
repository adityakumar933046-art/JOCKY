"""
JOCKY Forensic Indicator Models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class IndicatorType(str, Enum):
    IPV4 = "IPV4"
    DOMAIN = "DOMAIN"
    SHA256 = "SHA256"
    MD5 = "MD5"
    FILE_PATH = "FILE_PATH"
    PORT = "PORT"
    REGISTRY_KEY = "REGISTRY_KEY"
    PROCESS_NAME = "PROCESS_NAME"
    SERVICE_NAME = "SERVICE_NAME"
    DRIVER_NAME = "DRIVER_NAME"


@dataclass
class Indicator:
    indicator_id: str = field(default_factory=lambda: f"IOC-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    indicator_type: str = IndicatorType.IPV4.value
    value: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    occurrences: int = 1
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_artifacts: List[str] = field(default_factory=list)
    agents_observed: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "organization_id": self.organization_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "severity": self.severity,
            "source_artifacts": self.source_artifacts,
            "agents_observed": self.agents_observed,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Indicator":
        return cls(
            indicator_id=d.get("indicator_id", f"IOC-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            indicator_type=d.get("indicator_type", IndicatorType.IPV4.value),
            value=d.get("value", ""),
            first_seen=d.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=d.get("last_seen", datetime.now(timezone.utc).isoformat()),
            occurrences=int(d.get("occurrences", 1)),
            severity=d.get("severity", "INFO"),
            source_artifacts=d.get("source_artifacts", []),
            agents_observed=d.get("agents_observed", []),
            metadata=d.get("metadata", {}),
        )
