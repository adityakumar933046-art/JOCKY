"""
JOCKY Forensic Artifacts and Relationships REST API Endpoints.
Provides filtered access to normalized forensic artifacts and deterministic relationship graphs.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from server.database import get_db
from server.models.artifact import NormalizedArtifactModel, ArtifactRelationshipModel
from server.models.user import UserModel
from server.schemas.forensics import NormalizedArtifactResponse, ArtifactRelationshipResponse
from server.api.security import get_current_user, require_permission, check_org_access
from server.security.permissions import Permissions, Roles

artifacts_router = APIRouter(prefix="/artifacts", tags=["Forensic Artifacts"])
relationships_router = APIRouter(prefix="/relationships", tags=["Artifact Relationships"])


@artifacts_router.get("", response_model=List[NormalizedArtifactResponse])
def list_artifacts(
    artifact_type: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    evidence_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.ARTIFACTS_READ)),
):
    """List normalized forensic artifacts with multi-attribute filtering and org isolation."""
    query = db.query(NormalizedArtifactModel)

    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(NormalizedArtifactModel.organization_id == current_user.organization_id)

    if artifact_type:
        query = query.filter(NormalizedArtifactModel.artifact_type == artifact_type.upper())
    if agent_id:
        query = query.filter(NormalizedArtifactModel.agent_id == agent_id)
    if evidence_id:
        query = query.filter(NormalizedArtifactModel.evidence_id == evidence_id)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                NormalizedArtifactModel.hostname.ilike(search_term),
                NormalizedArtifactModel.artifact_type.ilike(search_term),
            )
        )

    return query.order_by(NormalizedArtifactModel.timestamp.desc()).offset(offset).limit(limit).all()


@artifacts_router.get("/{artifact_id}", response_model=NormalizedArtifactResponse)
def get_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.ARTIFACTS_READ)),
):
    """Retrieve details for a single normalized forensic artifact."""
    query = db.query(NormalizedArtifactModel).filter(NormalizedArtifactModel.artifact_id == artifact_id)
    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(NormalizedArtifactModel.organization_id == current_user.organization_id)

    art = query.first()
    if not art:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact {artifact_id} not found",
        )
    return art


@relationships_router.get("", response_model=List[ArtifactRelationshipResponse])
def list_relationships(
    source_artifact_id: Optional[str] = Query(None),
    target_artifact_id: Optional[str] = Query(None),
    relationship_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.ARTIFACTS_READ)),
):
    """List directional relationships between artifacts."""
    query = db.query(ArtifactRelationshipModel)
    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(ArtifactRelationshipModel.organization_id == current_user.organization_id)

    if source_artifact_id:
        query = query.filter(ArtifactRelationshipModel.source_artifact_id == source_artifact_id)
    if target_artifact_id:
        query = query.filter(ArtifactRelationshipModel.target_artifact_id == target_artifact_id)
    if relationship_type:
        query = query.filter(ArtifactRelationshipModel.relationship_type == relationship_type.upper())

    return query.order_by(ArtifactRelationshipModel.created_at.desc()).offset(offset).limit(limit).all()
