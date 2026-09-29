"""
JOCKY Job Management API Endpoints.
Enforces multi-tenancy organization boundaries, agent trust verification, and RBAC permissions.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from server.database import get_db
from server.models.job import JobModel
from server.models.user import UserModel
from server.schemas.job import (
    JobCreateRequest,
    JobResponse,
    JobStatusUpdateRequest,
    JobResultUploadRequest,
)
from server.services.job_service import JobService
from server.api.security import (
    verify_agent_auth,
    require_permission,
    check_org_access,
)
from server.security.permissions import Permissions, Roles

router = APIRouter(prefix="/jobs", tags=["Jobs"])


@router.post("", response_model=JobResponse)
def create_job(
    req: JobCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.JOBS_CREATE)),
):
    """Create a new forensic job. Validates JOCKY source, IR Allow-List, and agent trust state."""
    return JobService.create_job(db, req, user=user)


@router.get("", response_model=List[JobResponse])
def list_jobs(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.JOBS_READ)),
):
    """List forensic jobs with multi-tenant filtering."""
    query = db.query(JobModel)

    if user.role != Roles.SUPER_ADMIN:
        query = query.filter(JobModel.organization_id == user.organization_id)

    if agent_id:
        query = query.filter(JobModel.agent_id == agent_id)
    if status:
        query = query.filter(JobModel.status == status.upper())
    return query.order_by(JobModel.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(require_permission(Permissions.JOBS_READ)),
):
    """Retrieve details for a single job with organization access control."""
    job = db.query(JobModel).filter(JobModel.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    if not check_org_access(user, job.organization_id):
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization job access denied.")

    return job


@router.post("/{job_id}/status", response_model=JobResponse)
def update_job_status(
    job_id: str,
    req: JobStatusUpdateRequest,
    agent_id: str = Query(...),
    db: Session = Depends(get_db),
    auth: str = Depends(verify_agent_auth),
):
    """Agent updates job execution state (e.g. ASSIGNED -> RUNNING)."""
    return JobService.update_job_status(db, job_id, agent_id, req.status, req.error)


@router.post("/{job_id}/results", response_model=JobResponse)
def upload_job_results(
    job_id: str,
    req: JobResultUploadRequest,
    db: Session = Depends(get_db),
    auth: str = Depends(verify_agent_auth),
):
    """Agent uploads captured evidence records and threat findings upon job completion."""
    if req.job_id != job_id:
        raise HTTPException(status_code=400, detail="Mismatched path job_id and payload job_id.")
    return JobService.process_job_results(db, req)
