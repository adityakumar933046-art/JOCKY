"""
JOCKY Forensic Evidence Models.

Defines structured data models for captured forensic evidence records.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass
class EvidenceRecord:
    """A standardized forensic evidence record."""
    evidence_id: str = field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hostname: str = ""
    operating_system: str = ""
    collector: str = ""
    operation: str = ""
    collection_status: str = "success"  # "success", "partial", "error"
    data: Any = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence record to a clean dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "operating_system": self.operating_system,
            "collector": self.collector,
            "operation": self.operation,
            "collection_status": self.collection_status,
            "data": self.data,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRecord":
        return cls(
            evidence_id=d.get("evidence_id", f"EV-{uuid.uuid4().hex[:8].upper()}"),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            hostname=d.get("hostname", ""),
            operating_system=d.get("operating_system", ""),
            collector=d.get("collector", ""),
            operation=d.get("operation", ""),
            collection_status=d.get("collection_status", "success"),
            data=d.get("data", {}),
            metadata=d.get("metadata", {}),
        )
