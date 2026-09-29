"""
JOCKY Security Events & Metrics API Endpoints.
Provides incident monitoring, security metric aggregation, and anomaly alerts.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.audit import SecurityEventModel
from server.models.agent import AgentModel
from server.models.finding import CentralFindingModel
from server.models.investigation import InvestigationModel
from server.models.user import UserModel
from server.schemas.security import SecurityEventResponse, SecurityMetricsResponse
from server.security.permissions import Permissions, Roles
from server.api.security import require_permission

router = APIRouter(prefix="/security", tags=["Security Events & Metrics"])


@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: UserModel = Depends(require_permission(Permissions.SECURITY_READ)),
    db: Session = Depends(get_db),
):
    """Retrieve security events with filtering and multi-tenant scoping."""
    query = db.query(SecurityEventModel)

    if user.role != Roles.SUPER_ADMIN:
        query = query.filter(SecurityEventModel.organization_id == user.organization_id)

    if event_type:
        query = query.filter(SecurityEventModel.event_type == event_type)
    if severity:
        query = query.filter(SecurityEventModel.severity == severity.upper())

    return query.order_by(SecurityEventModel.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/metrics", response_model=SecurityMetricsResponse)
def get_security_metrics(
    user: UserModel = Depends(require_permission(Permissions.SECURITY_READ)),
    db: Session = Depends(get_db),
):
    """Aggregate live security telemetry for the Security Operations Dashboard."""
    agent_q = db.query(AgentModel)
    finding_q = db.query(CentralFindingModel)
    inv_q = db.query(InvestigationModel)
    sec_q = db.query(SecurityEventModel)

    if user.role != Roles.SUPER_ADMIN:
        agent_q = agent_q.filter(AgentModel.organization_id == user.organization_id)
        finding_q = finding_q.filter(CentralFindingModel.organization_id == user.organization_id)
        inv_q = inv_q.filter(InvestigationModel.organization_id == user.organization_id)
        sec_q = sec_q.filter(SecurityEventModel.organization_id == user.organization_id)

    auth_agents = agent_q.filter(AgentModel.trust_state == "AUTHORIZED").count()
    pend_agents = agent_q.filter(AgentModel.trust_state == "PENDING").count()
    susp_agents = agent_q.filter(AgentModel.trust_state == "SUSPENDED").count()
    revk_agents = agent_q.filter(AgentModel.trust_state == "REVOKED").count()

    auth_fails = sec_q.filter(SecurityEventModel.event_type == "AUTHENTICATION_FAILURE").count()
    authz_fails = sec_q.filter(SecurityEventModel.event_type == "AUTHORIZATION_FAILURE").count()
    integ_fails = sec_q.filter(SecurityEventModel.event_type == "INTEGRITY_FAILURE").count()

    open_invs = inv_q.filter(InvestigationModel.status != "CLOSED").count()
    crit_finds = finding_q.filter(CentralFindingModel.severity == "CRITICAL").count()
    high_finds = finding_q.filter(CentralFindingModel.severity == "HIGH").count()

    recent_events = (
        sec_q.order_by(SecurityEventModel.timestamp.desc())
        .limit(10)
        .all()
    )

    return SecurityMetricsResponse(
        authorized_agents=auth_agents,
        pending_agents=pend_agents,
        suspended_agents=susp_agents,
        revoked_agents=revk_agents,
        authentication_failures=auth_fails,
        authorization_failures=authz_fails,
        integrity_failures=integ_fails,
        open_investigations=open_invs,
        critical_findings=crit_finds,
        high_findings=high_finds,
        recent_security_events=recent_events,
    )
