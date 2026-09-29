"""
JOCKY Forensic Normalization Data Models.
Defines standard schema types and data structures for normalized forensic artifacts and relationships.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class NormalizedArtifactType(str, Enum):
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    FILE = "FILE"
    SERVICE = "SERVICE"
    DRIVER = "DRIVER"
    PERSISTENCE = "PERSISTENCE"
    MEMORY = "MEMORY"
    SYSTEM = "SYSTEM"
    USER = "USER"
    EVENT = "EVENT"


class RelationshipType(str, Enum):
    PARENT_OF = "PARENT_OF"
    CHILD_OF = "CHILD_OF"
    CREATED = "CREATED"
    SPAWNED = "SPAWNED"
    CONNECTED_TO = "CONNECTED_TO"
    LISTENING_ON = "LISTENING_ON"
    LOCATED_AT = "LOCATED_AT"
    EXECUTED_FROM = "EXECUTED_FROM"
    REGISTERED_AS = "REGISTERED_AS"
    LOADED_BY = "LOADED_BY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    OBSERVED_ON = "OBSERVED_ON"
    RELATED_TO = "RELATED_TO"


@dataclass
class NormalizedArtifact:
    """A standardized forensic artifact normalized across heterogeneous operating systems."""
    artifact_id: str = field(default_factory=lambda: f"ART-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    agent_id: str = ""
    evidence_id: str = ""
    job_id: Optional[str] = None
    hostname: str = ""
    artifact_type: str = NormalizedArtifactType.PROCESS.value
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    normalized_attributes: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "organization_id": self.organization_id,
            "agent_id": self.agent_id,
            "evidence_id": self.evidence_id,
            "job_id": self.job_id,
            "hostname": self.hostname,
            "artifact_type": self.artifact_type,
            "timestamp": self.timestamp,
            "normalized_attributes": self.normalized_attributes,
            "raw_data": self.raw_data,
            "indicators": self.indicators,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NormalizedArtifact":
        return cls(
            artifact_id=d.get("artifact_id", f"ART-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            agent_id=d.get("agent_id", ""),
            evidence_id=d.get("evidence_id", ""),
            job_id=d.get("job_id"),
            hostname=d.get("hostname", ""),
            artifact_type=d.get("artifact_type", NormalizedArtifactType.PROCESS.value),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            normalized_attributes=d.get("normalized_attributes", {}),
            raw_data=d.get("raw_data", {}),
            indicators=d.get("indicators", []),
        )


@dataclass
class ArtifactRelationship:
    """A typed directional relationship between two normalized artifacts with confidence and citations."""
    relationship_id: str = field(default_factory=lambda: f"REL-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = "org-default"
    source_artifact_id: str = ""
    target_artifact_id: str = ""
    relationship_type: str = RelationshipType.ASSOCIATED_WITH.value
    confidence: float = 1.0
    evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "organization_id": self.organization_id,
            "source_artifact_id": self.source_artifact_id,
            "target_artifact_id": self.target_artifact_id,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ArtifactRelationship":
        return cls(
            relationship_id=d.get("relationship_id", f"REL-{uuid.uuid4().hex[:8].upper()}"),
            organization_id=d.get("organization_id", "org-default"),
            source_artifact_id=d.get("source_artifact_id", ""),
            target_artifact_id=d.get("target_artifact_id", ""),
            relationship_type=d.get("relationship_type", RelationshipType.ASSOCIATED_WITH.value),
            confidence=float(d.get("confidence", 1.0)),
            evidence_ids=d.get("evidence_ids", []),
            metadata=d.get("metadata", {}),
        )
