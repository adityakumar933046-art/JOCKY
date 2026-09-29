"""
JOCKY Investigation Note and Snapshot Database Models.
Supports collaborative analyst notes and frozen point-in-time case snapshots.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from server.database import Base


class InvestigationNoteModel(Base):
    __tablename__ = "investigation_notes"

    note_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    author_id = Column(String(64), nullable=False)
    author_name = Column(String(128), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    investigation = relationship("InvestigationModel", backref="notes")


class InvestigationSnapshotModel(Base):
    __tablename__ = "investigation_snapshots"

    snapshot_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    title = Column(String(255), nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    snapshot_data = Column(JSON, nullable=False)

    investigation = relationship("InvestigationModel", backref="snapshots")
