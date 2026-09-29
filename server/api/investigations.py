"""
JOCKY Investigation Management, Graph, Notes, Snapshots, and Timeline API Endpoints.
Enforces multi-tenancy organization scoping, RBAC permissions, and comprehensive workspace capabilities.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.user import UserModel
from server.models.investigation import InvestigationModel
from server.models.artifact import NormalizedArtifactModel, ArtifactRelationshipModel
from server.models.indicator import IndicatorModel
from server.models.investigation_note import InvestigationNoteModel, InvestigationSnapshotModel
from server.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationUpdateRequest,
    InvestigationResponse,
    TimelineResponse,
)
from server.schemas.forensics import (
    NormalizedArtifactResponse,
    IndicatorResponse,
    InvestigationGraphResponse,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
    InvestigationSnapshotCreate,
    InvestigationSnapshotResponse,
)
from server.services.investigation_service import InvestigationService
from server.api.security import (
    require_permission,
    check_org_access,
)
from server.security.permissions import Permissions, Roles
from server.security.audit_service import AuditService

from forensics.graph.engine import default_graph_engine
from forensics.indicators.extractor import default_indicator_extractor
from forensics.normalization.models import NormalizedArtifact, ArtifactRelationship

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.post("", response_model=InvestigationResponse)
def create_investigation(
    req: InvestigationCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_CREATE)),
):
    """Create a new forensic investigation case within user's organization."""
    return InvestigationService.create_investigation(db, req, user=user)


@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """List all open and past forensic investigations for user's organization."""
    org_id = user.organization_id if user.role != Roles.SUPER_ADMIN else None
    return InvestigationService.get_all(db, organization_id=org_id)


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Get investigation details with cross-organization protection."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization investigation access denied.")

    return inv


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
def update_investigation(
    investigation_id: str,
    req: InvestigationUpdateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_UPDATE)),
):
    """Update investigation metadata or associate assets."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization update denied.")

    return InvestigationService.update_investigation(db, investigation_id, req, user=user)


@router.get("/{investigation_id}/timeline", response_model=TimelineResponse)
def get_investigation_timeline(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Generate a unified, chronologically sorted forensic investigation timeline."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization timeline access denied.")

    return InvestigationService.generate_timeline(db, investigation_id)


@router.get("/{investigation_id}/graph", response_model=InvestigationGraphResponse)
def get_investigation_graph(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Generate an interactive forensic entity relationship graph for the investigation."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    # Collect Evidence IDs and Agent IDs
    evidence_ids = [ev.evidence_id for ev in inv.evidence]
    agent_ids = [ag.agent_id for ag in inv.agents]

    # Fetch Normalized Artifacts
    artifacts_query = db.query(NormalizedArtifactModel).filter(
        (NormalizedArtifactModel.evidence_id.in_(evidence_ids)) |
        (NormalizedArtifactModel.agent_id.in_(agent_ids))
    )
    if user.role != Roles.SUPER_ADMIN:
        artifacts_query = artifacts_query.filter(NormalizedArtifactModel.organization_id == user.organization_id)
    db_artifacts = artifacts_query.all()

    norm_artifacts: List[NormalizedArtifact] = [
        NormalizedArtifact(
            artifact_id=a.artifact_id,
            organization_id=a.organization_id,
            agent_id=a.agent_id,
            evidence_id=a.evidence_id,
            job_id=a.job_id,
            hostname=a.hostname,
            artifact_type=a.artifact_type,
            timestamp=a.timestamp.isoformat() if a.timestamp else "",
            normalized_attributes=a.normalized_attributes or {},
            raw_data=a.raw_data or {},
            indicators=a.indicators or [],
        )
        for a in db_artifacts
    ]

    # Fetch Relationships between these artifacts
    art_ids = [a.artifact_id for a in db_artifacts]
    relationships_query = db.query(ArtifactRelationshipModel).filter(
        ArtifactRelationshipModel.source_artifact_id.in_(art_ids),
        ArtifactRelationshipModel.target_artifact_id.in_(art_ids),
    )
    db_relationships = relationships_query.all()

    norm_relationships: List[ArtifactRelationship] = [
        ArtifactRelationship(
            relationship_id=r.relationship_id,
            organization_id=r.organization_id,
            source_artifact_id=r.source_artifact_id,
            target_artifact_id=r.target_artifact_id,
            relationship_type=r.relationship_type,
            confidence=r.confidence,
            evidence_ids=r.evidence_ids or [],
            metadata=r.metadata_json or {},
        )
        for r in db_relationships
    ]

    # Extract indicators
    extracted_indicators = default_indicator_extractor.extract_from_artifacts(
        artifacts=norm_artifacts,
        organization_id=inv.organization_id,
    )

    # Build Graph
    graph = default_graph_engine.build_graph(
        investigation_id=investigation_id,
        agents=inv.agents,
        artifacts=norm_artifacts,
        relationships=norm_relationships,
        indicators=extracted_indicators,
        findings=inv.findings,
    )

    return graph.to_dict()


@router.get("/{investigation_id}/artifacts", response_model=List[NormalizedArtifactResponse])
def get_investigation_artifacts(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Retrieve all normalized artifacts linked to this investigation."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    evidence_ids = [ev.evidence_id for ev in inv.evidence]
    agent_ids = [ag.agent_id for ag in inv.agents]

    query = db.query(NormalizedArtifactModel).filter(
        (NormalizedArtifactModel.evidence_id.in_(evidence_ids)) |
        (NormalizedArtifactModel.agent_id.in_(agent_ids))
    )
    if user.role != Roles.SUPER_ADMIN:
        query = query.filter(NormalizedArtifactModel.organization_id == user.organization_id)

    return query.order_by(NormalizedArtifactModel.timestamp.desc()).all()


@router.get("/{investigation_id}/indicators", response_model=List[IndicatorResponse])
def get_investigation_indicators(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Retrieve all IOC indicators extracted from artifacts in this investigation."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    agent_ids = [ag.agent_id for ag in inv.agents]
    evidence_ids = [ev.evidence_id for ev in inv.evidence]

    # Find artifacts
    db_artifacts = db.query(NormalizedArtifactModel).filter(
        (NormalizedArtifactModel.evidence_id.in_(evidence_ids)) |
        (NormalizedArtifactModel.agent_id.in_(agent_ids))
    ).all()

    norm_artifacts = [
        NormalizedArtifact(
            artifact_id=a.artifact_id,
            organization_id=a.organization_id,
            agent_id=a.agent_id,
            evidence_id=a.evidence_id,
            job_id=a.job_id,
            hostname=a.hostname,
            artifact_type=a.artifact_type,
            timestamp=a.timestamp.isoformat() if a.timestamp else "",
            normalized_attributes=a.normalized_attributes or {},
            raw_data=a.raw_data or {},
            indicators=a.indicators or [],
        )
        for a in db_artifacts
    ]

    extracted = default_indicator_extractor.extract_from_artifacts(norm_artifacts, organization_id=inv.organization_id)
    return [
        IndicatorResponse(
            indicator_id=i.indicator_id,
            organization_id=i.organization_id,
            indicator_type=i.indicator_type,
            value=i.value,
            first_seen=datetime.fromisoformat(i.first_seen),
            last_seen=datetime.fromisoformat(i.last_seen),
            occurrences=i.occurrences,
            severity=i.severity,
            source_artifacts=i.source_artifacts,
            agents_observed=i.agents_observed,
            metadata_json=i.metadata,
        )
        for i in extracted
    ]


@router.get("/{investigation_id}/notes", response_model=List[InvestigationNoteResponse])
def get_investigation_notes(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """List all collaborative analyst notes for the investigation."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    notes = db.query(InvestigationNoteModel).filter(
        InvestigationNoteModel.investigation_id == investigation_id
    ).order_by(InvestigationNoteModel.created_at.desc()).all()
    return notes


@router.post("/{investigation_id}/notes", response_model=InvestigationNoteResponse)
def add_investigation_note(
    investigation_id: str,
    req: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_UPDATE)),
):
    """Add a collaborative note to an investigation case."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization update denied.")

    note = InvestigationNoteModel(
        note_id=f"NOTE-{uuid.uuid4().hex[:8].upper()}",
        investigation_id=investigation_id,
        organization_id=inv.organization_id,
        author_id=user.user_id,
        author_name=user.username,
        content=req.content,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="INVESTIGATION_NOTE_ADDED",
        resource_type="INVESTIGATION",
        resource_id=investigation_id,
        organization_id=inv.organization_id,
        result="SUCCESS",
        details={"note_id": note.note_id},
    )

    return note


@router.delete("/{investigation_id}/notes/{note_id}")
def delete_investigation_note(
    investigation_id: str,
    note_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_UPDATE)),
):
    """Delete an investigation note."""
    note = db.query(InvestigationNoteModel).filter(
        InvestigationNoteModel.note_id == note_id,
        InvestigationNoteModel.investigation_id == investigation_id,
    ).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")

    if not check_org_access(user, note.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization note deletion denied.")

    db.delete(note)
    db.commit()
    return {"status": "DELETED", "note_id": note_id}


@router.post("/{investigation_id}/snapshots", response_model=InvestigationSnapshotResponse)
def create_investigation_snapshot(
    investigation_id: str,
    req: InvestigationSnapshotCreate,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_UPDATE)),
):
    """Freeze and capture a point-in-time snapshot of the investigation."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    timeline = InvestigationService.generate_timeline(db, investigation_id)
    notes = db.query(InvestigationNoteModel).filter(InvestigationNoteModel.investigation_id == investigation_id).all()

    snapshot_payload = {
        "investigation_id": inv.investigation_id,
        "title": inv.title,
        "description": inv.description,
        "status": inv.status,
        "agents": [{"agent_id": a.agent_id, "hostname": a.hostname, "os": a.operating_system} for a in inv.agents],
        "findings": [{"finding_id": f.finding_id, "title": f.title, "severity": f.severity} for f in inv.findings],
        "evidence": [{"evidence_id": e.evidence_id, "hash": e.content_hash, "operation": e.operation} for e in inv.evidence],
        "timeline_events_count": len(timeline.events),
        "notes": [{"note_id": n.note_id, "author": n.author_name, "content": n.content} for n in notes],
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }

    snap = InvestigationSnapshotModel(
        snapshot_id=f"SNAP-{uuid.uuid4().hex[:8].upper()}",
        investigation_id=investigation_id,
        organization_id=inv.organization_id,
        title=req.title,
        created_by=user.username,
        created_at=datetime.now(timezone.utc),
        snapshot_data=snapshot_payload,
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="INVESTIGATION_SNAPSHOT_CREATED",
        resource_type="INVESTIGATION",
        resource_id=investigation_id,
        organization_id=inv.organization_id,
        result="SUCCESS",
        details={"snapshot_id": snap.snapshot_id, "title": snap.title},
    )

    return snap


@router.get("/{investigation_id}/snapshots", response_model=List[InvestigationSnapshotResponse])
def list_investigation_snapshots(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """List point-in-time frozen snapshots for the case."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    return db.query(InvestigationSnapshotModel).filter(
        InvestigationSnapshotModel.investigation_id == investigation_id
    ).order_by(InvestigationSnapshotModel.created_at.desc()).all()


@router.get("/{investigation_id}/snapshots/{snapshot_id}", response_model=InvestigationSnapshotResponse)
def get_investigation_snapshot(
    investigation_id: str,
    snapshot_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.INVESTIGATIONS_READ)),
):
    """Retrieve details and frozen state of a point-in-time snapshot."""
    snap = db.query(InvestigationSnapshotModel).filter(
        InvestigationSnapshotModel.snapshot_id == snapshot_id,
        InvestigationSnapshotModel.investigation_id == investigation_id,
    ).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found.")
    if not check_org_access(user, snap.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    return snap


@router.get("/{investigation_id}/report")
def get_investigation_report(
    investigation_id: str,
    format: str = Query("html", pattern="^(html|json)$"),
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.REPORTS_GENERATE)),
):
    """Export the comprehensive forensic investigation report in HTML or JSON format."""
    inv = InvestigationService.get_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    if not check_org_access(user, inv.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization report generation denied.")

    if format == "html":
        html_content = InvestigationService.generate_html_report(db, investigation_id, user=user)
        return Response(content=html_content, media_type="text/html")
    else:
        timeline = InvestigationService.generate_timeline(db, investigation_id)
        notes = db.query(InvestigationNoteModel).filter(InvestigationNoteModel.investigation_id == investigation_id).all()
        report_data = {
            "investigation": InvestigationResponse.model_validate(inv).model_dump(),
            "timeline": timeline.model_dump(),
            "notes": [{"note_id": n.note_id, "author": n.author_name, "content": n.content, "created_at": n.created_at.isoformat()} for n in notes],
        }
        return report_data
