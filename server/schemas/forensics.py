"""
JOCKY Forensic Pydantic Schemas for Step 6.
Supports normalized artifacts, relationships, indicators, correlation, graph, search, notes, and snapshots.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NormalizedArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    organization_id: str
    agent_id: str
    evidence_id: str
    job_id: Optional[str] = None
    hostname: str
    artifact_type: str
    timestamp: datetime
    normalized_attributes: Dict[str, Any] = Field(default_factory=dict)
    indicators: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class ArtifactRelationshipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    relationship_id: str
    organization_id: str
    source_artifact_id: str
    target_artifact_id: str
    relationship_type: str
    confidence: float
    evidence_ids: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class IndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    indicator_id: str
    organization_id: str
    indicator_type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    severity: str
    source_artifacts: List[str] = Field(default_factory=list)
    agents_observed: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class CrossSystemCorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    correlation_id: str
    organization_id: str
    indicator_type: str
    indicator_value: str
    agents_count: int
    agent_ids: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    severity: str
    linked_investigation_ids: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class CorrelatedFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    correlation_id: str
    organization_id: str
    title: str
    category: str
    severity: str
    confidence: float
    description: Optional[str] = None
    finding_ids: List[str] = Field(default_factory=list)
    artifact_ids: List[str] = Field(default_factory=list)
    indicator_ids: List[str] = Field(default_factory=list)
    agent_ids: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None


class GraphNodeSchema(BaseModel):
    id: str
    label: str
    type: str
    severity: str = "INFO"
    agent_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    confidence: float = 1.0
    evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationGraphResponse(BaseModel):
    investigation_id: str
    nodes: List[GraphNodeSchema] = Field(default_factory=list)
    edges: List[GraphEdgeSchema] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class InvestigationNoteCreate(BaseModel):
    content: str


class InvestigationNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    note_id: str
    investigation_id: str
    organization_id: str
    author_id: str
    author_name: str
    content: str
    created_at: datetime
    updated_at: datetime


class InvestigationSnapshotCreate(BaseModel):
    title: str


class InvestigationSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    snapshot_id: str
    investigation_id: str
    organization_id: str
    title: str
    created_by: str
    created_at: datetime
    snapshot_data: Dict[str, Any]


class SearchResultItem(BaseModel):
    entity_type: str
    entity_id: str
    title: str
    subtitle: str
    severity: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    query: str
    total_results: int
    results: List[SearchResultItem] = Field(default_factory=list)
