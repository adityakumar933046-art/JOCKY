"""
JOCKY Agent Management API Endpoints.
Implements agent trust lifecycle (PENDING -> AUTHORIZED -> SUSPENDED -> REVOKED),
per-agent credential generation, and heartbeat security.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from server.database import get_db
from server.config import config
from server.models.agent import AgentModel
from server.models.user import UserModel
from server.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentHeartbeatResponse,
    AgentResponse,
)
from server.schemas.job import JobResponse
from server.schemas.security import AgentTrustUpdateRequest
from server.services.job_service import JobService
from server.api.security import (
    verify_agent_auth,
    get_current_user,
    require_permission,
    check_org_access,
)
from server.security.permissions import Permissions, Roles
from server.security.crypto import generate_secure_token, hash_agent_token
from server.security.audit_service import AuditService

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("/register", response_model=AgentRegisterResponse)
def register_agent(
    req: AgentRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: str = Depends(verify_agent_auth),
):
    """Register a JOCKY endpoint agent. New agents start in PENDING trust state."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == req.agent_id).first()
    now = datetime.now(timezone.utc)
    raw_token = generate_secure_token(32)
    token_hash = hash_agent_token(raw_token)

    initial_trust = req.trust_state
    if not initial_trust:
        if config.ENVIRONMENT != "production" and (req.organization_id is None or req.organization_id == "org-default"):
            initial_trust = "AUTHORIZED"
        else:
            initial_trust = "PENDING"

    if not agent:
        agent = AgentModel(
            agent_id=req.agent_id,
            hostname=req.hostname,
            operating_system=req.operating_system,
            os_version=req.os_version,
            architecture=req.architecture,
            jocky_version=req.jocky_version,
            collector_version=req.collector_version,
            registered_at=now,
            last_seen=now,
            status="ONLINE",
            organization_id=req.organization_id or config.DEFAULT_ORG_ID,
            trust_state=initial_trust,
            agent_token_hash=token_hash,
        )
        db.add(agent)
        AuditService.log(
            db=db,
            actor_type="AGENT",
            actor_id=agent.agent_id,
            action="AGENT_REGISTERED",
            resource_type="AGENT",
            resource_id=agent.agent_id,
            organization_id=agent.organization_id,
            ip_address=request.client.host if request.client else None,
            result="SUCCESS",
            details={"trust_state": "PENDING", "hostname": agent.hostname},
        )
    else:
        # Existing agent re-registration preserves trust_state unless previously revoked
        if agent.trust_state == "REVOKED":
            AuditService.log_security_event(
                db=db,
                event_type="REVOKED_AGENT",
                description=f"Revoked agent '{agent.agent_id}' attempted re-registration.",
                severity="HIGH",
                actor_id=agent.agent_id,
                organization_id=agent.organization_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Agent '{agent.agent_id}' has been permanently revoked.",
            )

        agent.hostname = req.hostname
        agent.operating_system = req.operating_system
        agent.os_version = req.os_version
        agent.architecture = req.architecture
        agent.jocky_version = req.jocky_version
        agent.collector_version = req.collector_version
        agent.last_seen = now
        agent.agent_token_hash = token_hash

    db.commit()
    db.refresh(agent)

    return AgentRegisterResponse(
        registered=True,
        agent_id=agent.agent_id,
        status=agent.status,
        trust_state=agent.trust_state,
        agent_token=raw_token,
    )


@router.post("/{agent_id}/approve", response_model=AgentResponse)
def approve_agent(
    agent_id: str,
    req: Optional[AgentTrustUpdateRequest] = None,
    user: UserModel = Depends(require_permission(Permissions.AGENTS_APPROVE)),
    db: Session = Depends(get_db),
):
    """Administrator approves a PENDING or SUSPENDED agent into AUTHORIZED state."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    if not check_org_access(user, agent.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization agent access denied.")

    if agent.trust_state == "REVOKED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot approve an agent that has been permanently revoked.",
        )

    agent.trust_state = "AUTHORIZED"
    agent.status = "ONLINE"
    db.commit()
    db.refresh(agent)

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="AGENT_APPROVED",
        resource_type="AGENT",
        resource_id=agent.agent_id,
        organization_id=agent.organization_id,
        result="SUCCESS",
        details={"reason": req.reason if req else None},
    )
    return agent


@router.post("/{agent_id}/suspend", response_model=AgentResponse)
def suspend_agent(
    agent_id: str,
    req: Optional[AgentTrustUpdateRequest] = None,
    user: UserModel = Depends(require_permission(Permissions.AGENTS_SUSPEND)),
    db: Session = Depends(get_db),
):
    """Administrator suspends an agent, preventing it from executing jobs or heartbeating."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    if not check_org_access(user, agent.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization agent access denied.")

    agent.trust_state = "SUSPENDED"
    db.commit()
    db.refresh(agent)

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="AGENT_SUSPENDED",
        resource_type="AGENT",
        resource_id=agent.agent_id,
        organization_id=agent.organization_id,
        result="SUCCESS",
        details={"reason": req.reason if req else None},
    )
    return agent


@router.post("/{agent_id}/revoke", response_model=AgentResponse)
def revoke_agent(
    agent_id: str,
    req: Optional[AgentTrustUpdateRequest] = None,
    user: UserModel = Depends(require_permission(Permissions.AGENTS_REVOKE)),
    db: Session = Depends(get_db),
):
    """Administrator permanently revokes an agent. It cannot be reactivated."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    if not check_org_access(user, agent.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization agent access denied.")

    agent.trust_state = "REVOKED"
    agent.status = "OFFLINE"
    db.commit()
    db.refresh(agent)

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="AGENT_REVOKED",
        resource_type="AGENT",
        resource_id=agent.agent_id,
        organization_id=agent.organization_id,
        result="SUCCESS",
        details={"reason": req.reason if req else None},
    )
    return agent


@router.post("/{agent_id}/heartbeat", response_model=AgentHeartbeatResponse)
def agent_heartbeat(
    agent_id: str,
    db: Session = Depends(get_db),
    auth: str = Depends(verify_agent_auth),
):
    """Periodic heartbeat from an agent. Rejects suspended or revoked agents."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    # Enforce trust state: heartbeats must NOT reactivate SUSPENDED or REVOKED agents
    if agent.trust_state in ("SUSPENDED", "REVOKED"):
        AuditService.log_security_event(
            db=db,
            event_type="INVALID_AGENT" if agent.trust_state == "SUSPENDED" else "REVOKED_AGENT",
            description=f"Heartbeat rejected: Agent '{agent_id}' is in {agent.trust_state} state.",
            severity="HIGH",
            actor_id=agent_id,
            organization_id=agent.organization_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{agent_id}' is {agent.trust_state}. Heartbeat rejected.",
        )

    agent.last_seen = datetime.now(timezone.utc)
    if agent.trust_state == "AUTHORIZED":
        agent.status = "ONLINE"

    db.commit()
    db.refresh(agent)

    return AgentHeartbeatResponse(
        agent_id=agent.agent_id,
        status=agent.status,
        trust_state=agent.trust_state,
        last_seen=agent.last_seen,
    )


@router.get("", response_model=List[AgentResponse])
def list_agents(
    user: UserModel = Depends(require_permission(Permissions.AGENTS_READ)),
    db: Session = Depends(get_db),
):
    """List registered agents with multi-tenant filtering."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=config.HEARTBEAT_TIMEOUT_SECONDS)

    query = db.query(AgentModel)
    if user.role != Roles.SUPER_ADMIN:
        query = query.filter(AgentModel.organization_id == user.organization_id)

    agents = query.all()
    for agent in agents:
        if agent.last_seen:
            agent_ts = agent.last_seen.replace(tzinfo=timezone.utc) if agent.last_seen.tzinfo is None else agent.last_seen
            if agent_ts < cutoff and agent.status == "ONLINE":
                agent.status = "OFFLINE"
    db.commit()

    return agents


@router.get("/{agent_id}", response_model=AgentResponse)
def get_agent(
    agent_id: str,
    user: UserModel = Depends(require_permission(Permissions.AGENTS_READ)),
    db: Session = Depends(get_db),
):
    """Retrieve details for a single agent with organization access control."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    if not check_org_access(user, agent.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")

    return agent


@router.get("/{agent_id}/jobs/next", response_model=Optional[JobResponse])
def get_next_job(
    agent_id: str,
    db: Session = Depends(get_db),
    auth: str = Depends(verify_agent_auth),
):
    """Agent retrieves next assigned job. Only AUTHORIZED agents may receive jobs."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    if agent.trust_state != "AUTHORIZED":
        AuditService.log_security_event(
            db=db,
            event_type="INVALID_AGENT" if agent.trust_state != "REVOKED" else "REVOKED_AGENT",
            description=f"Job poll denied: Agent '{agent_id}' is in '{agent.trust_state}' state.",
            severity="MEDIUM",
            actor_id=agent_id,
            organization_id=agent.organization_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{agent_id}' is {agent.trust_state}. Cannot receive jobs until approved.",
        )

    job = JobService.get_next_job_for_agent(db, agent_id)
    return job
