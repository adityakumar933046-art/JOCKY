"""
JOCKY Forensic Indicator and Cross-System Correlation Models.
Supports IOC extraction, tracking, pivot searching, and multi-endpoint correlation.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer, JSON, UniqueConstraint
from server.database import Base


class IndicatorModel(Base):
    __tablename__ = "indicators"

    indicator_id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    indicator_type = Column(String(64), nullable=False, index=True)  # IPV4, DOMAIN, SHA256, MD5, FILE_PATH, PORT, REGISTRY_KEY, PROCESS_NAME, SERVICE_NAME, DRIVER_NAME
    value = Column(String(512), nullable=False, index=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    occurrences = Column(Integer, default=1)
    severity = Column(String(32), default="INFO", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_artifacts = Column(JSON, default=list)
    agents_observed = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("organization_id", "indicator_type", "value", name="uq_indicator_org_type_val"),
    )


class CrossSystemCorrelationModel(Base):
    __tablename__ = "cross_system_correlations"

    correlation_id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    indicator_type = Column(String(64), nullable=False, index=True)
    indicator_value = Column(String(512), nullable=False, index=True)
    agents_count = Column(Integer, default=0)
    agent_ids = Column(JSON, default=list)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    occurrences = Column(Integer, default=0)
    severity = Column(String(32), default="HIGH", index=True)
    linked_investigation_ids = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("organization_id", "indicator_type", "indicator_value", name="uq_xcorr_org_type_val"),
    )
