"""
JOCKY Audit Log & Security Event SQLAlchemy Models.
Append-only immutable record of all administrative, access, and security events.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from server.database import Base


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    audit_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    actor_type = Column(String(32), nullable=False)  # USER, AGENT, SYSTEM
    actor_id = Column(String(64), nullable=False, index=True)
    organization_id = Column(String(64), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True)
    ip_address = Column(String(64), nullable=True)
    result = Column(String(32), default="SUCCESS", nullable=False)  # SUCCESS, FAILURE
    details = Column(JSON, default=dict, nullable=False)


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    event_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)  # AUTHENTICATION_FAILURE, AUTHORIZATION_FAILURE, INTEGRITY_FAILURE, etc.
    severity = Column(String(32), default="MEDIUM", nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    source_ip = Column(String(64), nullable=True)
    actor_id = Column(String(64), nullable=True, index=True)
    organization_id = Column(String(64), nullable=True, index=True)
    description = Column(Text, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
