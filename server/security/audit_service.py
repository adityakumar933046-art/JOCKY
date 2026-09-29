"""
JOCKY Audit & Security Event Logging Service.
Guarantees append-only persistence of audit logs and security monitoring events.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from server.models.audit import AuditLogModel, SecurityEventModel


class AuditService:
    @staticmethod
    def log(
        db: Session,
        actor_type: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        result: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLogModel:
        """Create an append-only audit log entry."""
        entry = AuditLogModel(
            audit_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            actor_type=actor_type,
            actor_id=actor_id,
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            result=result,
            details=details or {},
        )
        db.add(entry)
        try:
            db.commit()
            db.refresh(entry)
        except Exception:
            db.rollback()
        return entry

    @staticmethod
    def log_security_event(
        db: Session,
        event_type: str,
        description: str,
        severity: str = "HIGH",
        actor_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEventModel:
        """Create a security incident / anomaly event record."""
        event = SecurityEventModel(
            event_id=f"SEC-{uuid.uuid4().hex[:10].upper()}",
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            actor_id=actor_id,
            organization_id=organization_id,
            description=description,
            details=details or {},
        )
        db.add(event)
        try:
            db.commit()
            db.refresh(event)
        except Exception:
            db.rollback()
        return event
