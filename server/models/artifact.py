"""
JOCKY Normalized Artifact and Relationship Database Models.
Supports structured forensic normalization, typed directional relationships,
and deterministic deduplication for advanced graph analysis.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from server.database import Base


class NormalizedArtifactModel(Base):
    __tablename__ = "normalized_artifacts"

    artifact_id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("central_evidence.evidence_id"), nullable=False, index=True)
    job_id = Column(String(64), ForeignKey("jobs.job_id"), nullable=True, index=True)
    hostname = Column(String(255), nullable=False)
    artifact_type = Column(String(64), nullable=False, index=True)  # PROCESS, NETWORK, FILE, SERVICE, DRIVER, PERSISTENCE, SYSTEM, USER, EVENT, MEMORY
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    normalized_attributes = Column(JSON, default=dict)
    raw_data = Column(JSON, default=dict)
    indicators = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    agent = relationship("AgentModel", foreign_keys=[agent_id])
    evidence = relationship("CentralEvidenceModel", foreign_keys=[evidence_id])
    job = relationship("JobModel", foreign_keys=[job_id])


class ArtifactRelationshipModel(Base):
    __tablename__ = "artifact_relationships"

    relationship_id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    source_artifact_id = Column(String(64), ForeignKey("normalized_artifacts.artifact_id"), nullable=False, index=True)
    target_artifact_id = Column(String(64), ForeignKey("normalized_artifacts.artifact_id"), nullable=False, index=True)
    relationship_type = Column(String(64), nullable=False, index=True)  # PARENT_OF, CONNECTED_TO, LOCATED_AT, etc.
    confidence = Column(Float, default=1.0)
    evidence_ids = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("source_artifact_id", "target_artifact_id", "relationship_type", name="uq_artifact_rel"),
    )

    source_artifact = relationship("NormalizedArtifactModel", foreign_keys=[source_artifact_id])
    target_artifact = relationship("NormalizedArtifactModel", foreign_keys=[target_artifact_id])
