"""
JOCKY Organization SQLAlchemy Model.
Multi-tenant isolation boundary for users, endpoints, jobs, evidence, and investigations.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from server.database import Base


class OrganizationModel(Base):
    __tablename__ = "organizations"

    organization_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, SUSPENDED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
