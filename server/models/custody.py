"""
JOCKY Evidence Custody Event SQLAlchemy Model.
Maintains an immutable, cryptographically chained record of evidence custody transitions.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from server.database import Base


class EvidenceCustodyEventModel(Base):
    __tablename__ = "evidence_custody_events"

    event_id = Column(String(64), primary_key=True, index=True)
    evidence_id = Column(String(64), ForeignKey("central_evidence.evidence_id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    actor_type = Column(String(32), nullable=False)  # USER, AGENT, SYSTEM
    actor_id = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)      # COLLECTED, RECEIVED, VERIFIED, VIEWED, EXPORTED, ASSOCIATED_WITH_INVESTIGATION
    previous_hash = Column(String(64), default="", nullable=False)
    event_hash = Column(String(64), nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
