"""
JOCKY Central Evidence API Endpoints.
Provides multi-tenant evidence querying, access auditing, and cryptographic chain of custody.
"""

from typing import List, Optional
import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.user import UserModel
from server.models.custody import EvidenceCustodyEventModel
from server.schemas.evidence import EvidenceResponse
from server.schemas.security import CustodyEventResponse
from server.services.evidence_service import EvidenceService
from server.api.security import require_permission, check_org_access
from server.security.permissions import Permissions, Roles
from server.security.crypto import compute_event_hash
from server.security.audit_service import AuditService

router = APIRouter(prefix="/evidence", tags=["Evidence"])


@router.get("", response_model=List[EvidenceResponse])
def list_evidence(
    agent_id: Optional[str] = None,
    job_id: Optional[str] = None,
    operation: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserModel = Depends(require_permission(Permissions.EVIDENCE_READ)),
    db: Session = Depends(get_db),
):
    """Query central evidence records with organization boundary isolation."""
    org_id = user.organization_id if user.role != Roles.SUPER_ADMIN else None
    return EvidenceService.get_evidence(
        db=db,
        organization_id=org_id,
        agent_id=agent_id,
        job_id=job_id,
        operation=operation,
        limit=limit,
        offset=offset,
    )


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence_item(
    evidence_id: str,
    user: UserModel = Depends(require_permission(Permissions.EVIDENCE_READ)),
    db: Session = Depends(get_db),
):
    """Retrieve an individual evidence record, auditing the access in chain of custody."""
    item = EvidenceService.get_by_id(db, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    if not check_org_access(user, item.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization evidence access denied.")

    # Record chain of custody VIEWED event using tip of hash chain
    custody_chain = EvidenceService.get_custody_events(db, evidence_id)
    prev_hash = custody_chain[-1].event_hash if custody_chain else ""
    now = datetime.now(timezone.utc)
    evt_hash = compute_event_hash(prev_hash, now.isoformat(), user.user_id, "VIEWED", evidence_id)

    custody_view = EvidenceCustodyEventModel(
        event_id=f"CUST-{uuid.uuid4().hex[:8].upper()}",
        evidence_id=evidence_id,
        timestamp=now,
        actor_type="USER",
        actor_id=user.user_id,
        action="VIEWED",
        previous_hash=prev_hash,
        event_hash=evt_hash,
        metadata_json=json.dumps({"role": user.role, "operation": item.operation}),
    )
    db.add(custody_view)

    # Immutable audit log (without sensitive payload)
    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="EVIDENCE_VIEWED",
        resource_type="EVIDENCE",
        resource_id=evidence_id,
        organization_id=item.organization_id,
        result="SUCCESS",
        details={"operation": item.operation, "integrity_verified": item.integrity_verified},
    )

    db.commit()
    return item


@router.get("/{evidence_id}/custody", response_model=List[CustodyEventResponse])
def get_evidence_custody(
    evidence_id: str,
    user: UserModel = Depends(require_permission(Permissions.EVIDENCE_READ)),
    db: Session = Depends(get_db),
):
    """Retrieve chronological chain of custody events with cryptographic hashes."""
    item = EvidenceService.get_by_id(db, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    if not check_org_access(user, item.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization custody access denied.")

    return EvidenceService.get_custody_events(db, evidence_id)
