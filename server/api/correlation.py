"""
JOCKY Forensic Correlation REST API Endpoints.
Provides cross-system correlation, multi-stage attack campaign findings, and on-demand correlation analysis.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.indicator import CrossSystemCorrelationModel
from server.models.correlation import CorrelatedFindingModel
from server.models.user import UserModel
from server.schemas.forensics import CrossSystemCorrelationResponse, CorrelatedFindingResponse
from server.api.security import get_current_user, require_permission
from server.security.permissions import Permissions, Roles
from server.services.correlation_service import CorrelationService

correlation_router = APIRouter(prefix="/correlation", tags=["Forensic Correlation"])


@correlation_router.get("/cross-system", response_model=List[CrossSystemCorrelationResponse])
def list_cross_system_correlations(
    indicator_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.CORRELATION_READ)),
):
    """List indicators identified across multiple endpoints."""
    query = db.query(CrossSystemCorrelationModel)
    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(CrossSystemCorrelationModel.organization_id == current_user.organization_id)

    if indicator_type:
        query = query.filter(CrossSystemCorrelationModel.indicator_type == indicator_type.upper())
    if severity:
        query = query.filter(CrossSystemCorrelationModel.severity == severity.upper())
    if search:
        query = query.filter(CrossSystemCorrelationModel.indicator_value.ilike(f"%{search}%"))

    return query.order_by(CrossSystemCorrelationModel.agents_count.desc(), CrossSystemCorrelationModel.last_seen.desc()).offset(offset).limit(limit).all()


@correlation_router.get("/findings", response_model=List[CorrelatedFindingResponse])
def list_correlated_findings(
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.CORRELATION_READ)),
):
    """List correlated threat chains and campaign findings."""
    query = db.query(CorrelatedFindingModel)
    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(CorrelatedFindingModel.organization_id == current_user.organization_id)

    if category:
        query = query.filter(CorrelatedFindingModel.category == category.upper())
    if severity:
        query = query.filter(CorrelatedFindingModel.severity == severity.upper())

    return query.order_by(CorrelatedFindingModel.created_at.desc()).offset(offset).limit(limit).all()


@correlation_router.post("/run")
def trigger_correlation_run(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.CORRELATION_RUN)),
):
    """
    Execute full forensic normalization, indicator extraction, and correlation analysis
    across all evidence in the user's organization.
    """
    org_id = current_user.organization_id
    stats = CorrelationService.run_for_organization(db, org_id)
    return {
        "status": "COMPLETED",
        **stats,
    }
