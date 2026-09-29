"""
JOCKY Central Threat Findings API Endpoints.
Enforces multi-tenancy organization filtering and RBAC permissions.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.user import UserModel
from server.schemas.finding import FindingResponse
from server.services.finding_service import FindingService
from server.api.security import require_permission, check_org_access
from server.security.permissions import Permissions, Roles

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=List[FindingResponse])
def list_findings(
    agent_id: Optional[str] = None,
    job_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserModel = Depends(require_permission(Permissions.FINDINGS_READ)),
    db: Session = Depends(get_db),
):
    """Query threat findings with multi-tenant filtering."""
    org_id = user.organization_id if user.role != Roles.SUPER_ADMIN else None
    return FindingService.get_findings(
        db=db,
        organization_id=org_id,
        agent_id=agent_id,
        job_id=job_id,
        severity=severity,
        category=category,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_item(
    finding_id: str,
    user: UserModel = Depends(require_permission(Permissions.FINDINGS_READ)),
    db: Session = Depends(get_db),
):
    """Retrieve an individual threat finding with organization access check."""
    item = FindingService.get_by_id(db, finding_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    if not check_org_access(user, item.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization finding access denied.")

    return item
