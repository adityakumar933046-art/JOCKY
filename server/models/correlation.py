"""
JOCKY Correlated Finding Database Model.
Represents multi-finding threat chains, attack stages, and campaign correlations.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Float, JSON
from server.database import Base


class CorrelatedFindingModel(Base):
    __tablename__ = "correlated_findings"

    correlation_id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, default=0.85)
    description = Column(Text, nullable=True)
    finding_ids = Column(JSON, default=list)
    artifact_ids = Column(JSON, default=list)
    indicator_ids = Column(JSON, default=list)
    agent_ids = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
