"""
JOCKY Forensic Timeline Models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class TimelineEvent:
    event_id: str = field(default_factory=lambda: f"TLE-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    investigation_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "GENERIC_EVENT"
    category: str = "SYSTEM"  # PROCESS, NETWORK, FILE, SERVICE, DRIVER, PERSISTENCE, THREAT, NOTE, SYSTEM
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str = ""
    description: str = ""
    source_id: str = ""
    source_type: str = "artifact"
    agent_id: str = ""
    hostname: str = ""
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "organization_id": self.organization_id,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TimelineEvent":
        return cls(
            event_id=d.get("event_id", f"TLE-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            investigation_id=d.get("investigation_id"),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event_type=d.get("event_type", "GENERIC_EVENT"),
            category=d.get("category", "SYSTEM"),
            severity=d.get("severity", "INFO"),
            title=d.get("title", ""),
            description=d.get("description", ""),
            source_id=d.get("source_id", ""),
            source_type=d.get("source_type", "artifact"),
            agent_id=d.get("agent_id", ""),
            hostname=d.get("hostname", ""),
            indicators=d.get("indicators", []),
            metadata=d.get("metadata", {}),
        )
