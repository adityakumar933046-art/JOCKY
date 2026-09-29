"""
JOCKY Audit Log API Endpoints.
Immutable append-only access to platform activity logs.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.audit import AuditLogModel
from server.models.user import UserModel
from server.schemas.security import AuditLogResponse
from server.security.permissions import Permissions, Roles
from server.api.security import require_permission

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    actor_id: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    result: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserModel = Depends(require_permission(Permissions.AUDIT_READ)),
    db: Session = Depends(get_db),
):
    """Query immutable audit logs with multi-tenant isolation and field filtering."""
    query = db.query(AuditLogModel)

    # Multi-tenant isolation: non-superadmins only view their organization's logs
    if user.role != Roles.SUPER_ADMIN:
        query = query.filter(AuditLogModel.organization_id == user.organization_id)

    if actor_id:
        query = query.filter(AuditLogModel.actor_id == actor_id)
    if action:
        query = query.filter(AuditLogModel.action == action)
    if resource_type:
        query = query.filter(AuditLogModel.resource_type == resource_type)
    if result:
        query = query.filter(AuditLogModel.result == result.upper())
    if start_time:
        query = query.filter(AuditLogModel.timestamp >= start_time)
    if end_time:
        query = query.filter(AuditLogModel.timestamp <= end_time)

    return query.order_by(AuditLogModel.timestamp.desc()).offset(offset).limit(limit).all()
