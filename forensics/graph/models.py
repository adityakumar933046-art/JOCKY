"""
JOCKY Forensic Investigation Graph Models.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class GraphNode:
    id: str
    label: str
    type: str  # SYSTEM, PROCESS, FILE, NETWORK, SERVICE, DRIVER, PERSISTENCE, INDICATOR, FINDING
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    agent_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.type,
            "severity": self.severity,
            "agent_id": self.agent_id,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    relationship: str  # PARENT_OF, CONNECTED_TO, LOCATED_AT, ASSOCIATED_WITH, OBSERVED_ON, RELATED_TO, SPAWNED
    confidence: float = 1.0
    evidence_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "metadata": self.metadata,
        }


@dataclass
class InvestigationGraph:
    investigation_id: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "metrics": self.metrics,
        }
