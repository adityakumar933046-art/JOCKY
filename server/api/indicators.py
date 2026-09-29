"""
JOCKY Forensic Indicators REST API Endpoints.
Provides searchable, filterable threat indicators and IOC indexing.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.indicator import IndicatorModel
from server.models.user import UserModel
from server.schemas.forensics import IndicatorResponse
from server.api.security import get_current_user, require_permission
from server.security.permissions import Permissions, Roles

indicators_router = APIRouter(prefix="/indicators", tags=["Forensic Indicators"])


@indicators_router.get("", response_model=List[IndicatorResponse])
def list_indicators(
    indicator_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    min_occurrences: int = Query(1, ge=1),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.INDICATORS_READ)),
):
    """List forensic indicators with multi-attribute filtering and org isolation."""
    query = db.query(IndicatorModel)

    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(IndicatorModel.organization_id == current_user.organization_id)

    if indicator_type:
        query = query.filter(IndicatorModel.indicator_type == indicator_type.upper())
    if severity:
        query = query.filter(IndicatorModel.severity == severity.upper())
    if min_occurrences > 1:
        query = query.filter(IndicatorModel.occurrences >= min_occurrences)
    if search:
        query = query.filter(IndicatorModel.value.ilike(f"%{search}%"))

    return query.order_by(IndicatorModel.occurrences.desc(), IndicatorModel.last_seen.desc()).offset(offset).limit(limit).all()


@indicators_router.get("/{indicator_id}", response_model=IndicatorResponse)
def get_indicator(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_permission(Permissions.INDICATORS_READ)),
):
    """Retrieve details for a single forensic indicator."""
    query = db.query(IndicatorModel).filter(IndicatorModel.indicator_id == indicator_id)
    if current_user.role != Roles.SUPER_ADMIN:
        query = query.filter(IndicatorModel.organization_id == current_user.organization_id)

    ind = query.first()
    if not ind:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator {indicator_id} not found",
        )
    return ind
