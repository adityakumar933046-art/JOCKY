"""
JOCKY Job Service.
Handles job creation, compilation validation, IR allow-list enforcement,
agent trust verification, multi-tenant isolation, and SHA-256 evidence integrity verification.
"""

from datetime import datetime, timezone
import uuid
import json
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from server.models.job import JobModel
from server.models.agent import AgentModel
from server.models.evidence import CentralEvidenceModel
from server.models.finding import CentralFindingModel
from server.models.custody import EvidenceCustodyEventModel
from server.models.user import UserModel
from server.schemas.job import JobCreateRequest, JobResultUploadRequest
from compiler.compiler import Compiler
from compiler.ir import IRInstruction
from server.security.crypto import compute_canonical_evidence_hash, compute_event_hash
from server.security.audit_service import AuditService
from server.security.permissions import Roles


class IRAllowListError(Exception):
    """Raised when JOCKY source emits an unapproved IR instruction."""
    pass


class JobService:
    ALLOWED_OPCODES = {"SYSTEM_INFO", "SCAN", "ANALYZE", "REPORT", "DETECT"}
    ALLOWED_SCAN_TARGETS = {"PROCESSES", "NETWORK", "FILES", "DRIVERS", "SERVICES"}
    ALLOWED_ANALYZE_TARGETS = {"PERSISTENCE", "MEMORY", "NETWORK"}

    @classmethod
    def validate_jocky_source_and_ir(cls, source_code: str) -> List[IRInstruction]:
        """Compile JOCKY source and strictly enforce the IR Allow-List.
        
        Guarantees that agents only ever execute safe, read-only forensic operations.
        Rejects shell commands, system modifications, or arbitrary code execution.
        """
        compiler = Compiler()
        result = compiler.compile(source_code)

        if not result.success:
            err_msg = "; ".join(result.errors)
            raise HTTPException(
                status_code=400,
                detail=f"JOCKY compilation failed: {err_msg}",
            )

        # Enforce IR Allow-List
        for inst in result.ir or []:
            opcode = inst.opcode.upper()
            if opcode not in cls.ALLOWED_OPCODES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Security violation: Disallowed IR opcode '{opcode}'.",
                )

            if opcode == "SCAN":
                target = (inst.target or "").upper()
                if target not in cls.ALLOWED_SCAN_TARGETS:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Security violation: Disallowed SCAN target '{target}'.",
                    )

            if opcode == "ANALYZE":
                target = (inst.target or "").upper()
                if target not in cls.ALLOWED_ANALYZE_TARGETS:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Security violation: Disallowed ANALYZE target '{target}'.",
                    )

        return result.ir or []

    @classmethod
    def create_job(cls, db: Session, req: JobCreateRequest, user: Optional[UserModel] = None) -> JobModel:
        """Create a new validated job for an authorized agent, enforcing agent trust and org boundary."""
        # 1. Verify agent exists
        agent = db.query(AgentModel).filter(AgentModel.agent_id == req.agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{req.agent_id}' not found.")

        # Enforce multi-tenancy & trust state if user provided
        if user:
            if user.role != Roles.SUPER_ADMIN and agent.organization_id != user.organization_id:
                AuditService.log_security_event(
                    db=db,
                    event_type="AUTHORIZATION_FAILURE",
                    description=f"User '{user.username}' attempted cross-organization job creation on agent '{agent.agent_id}'.",
                    severity="HIGH",
                    actor_id=user.user_id,
                    organization_id=user.organization_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: Cannot create job for agent in a different organization.",
                )

            if agent.trust_state != "AUTHORIZED":
                AuditService.log_security_event(
                    db=db,
                    event_type="INVALID_AGENT",
                    description=f"Job creation rejected: Agent '{agent.agent_id}' is in '{agent.trust_state}' trust state.",
                    severity="MEDIUM",
                    actor_id=user.user_id,
                    organization_id=agent.organization_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Agent '{agent.agent_id}' is {agent.trust_state}. Jobs can only be assigned to AUTHORIZED agents.",
                )

        # 2. Validate JOCKY source and IR Allow-list
        cls.validate_jocky_source_and_ir(req.jocky_source)

        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        job = JobModel(
            job_id=job_id,
            name=req.name,
            agent_id=req.agent_id,
            organization_id=agent.organization_id,
            jocky_source=req.jocky_source,
            detection_enabled=req.detection_enabled,
            created_by=user.username if user else req.created_by,
            status="PENDING",
            created_at=datetime.now(timezone.utc),
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        AuditService.log(
            db=db,
            actor_type="USER" if user else "SYSTEM",
            actor_id=user.user_id if user else "system",
            action="JOB_CREATED",
            resource_type="JOB",
            resource_id=job.job_id,
            organization_id=job.organization_id,
            result="SUCCESS",
            details={"agent_id": job.agent_id, "name": job.name},
        )

        return job

    @classmethod
    def get_next_job_for_agent(cls, db: Session, agent_id: str) -> Optional[JobModel]:
        """Retrieve next pending job and transition status to ASSIGNED."""
        job = (
            db.query(JobModel)
            .filter(JobModel.agent_id == agent_id, JobModel.status == "PENDING")
            .order_by(JobModel.created_at.asc())
            .first()
        )
        if job:
            job.status = "ASSIGNED"
            job.submitted_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(job)
        return job

    @classmethod
    def update_job_status(cls, db: Session, job_id: str, agent_id: str, status_str: str, error: Optional[str] = None) -> JobModel:
        """Update job lifecycle status (e.g., ASSIGNED -> RUNNING)."""
        job = db.query(JobModel).filter(JobModel.job_id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
        if job.agent_id != agent_id:
            raise HTTPException(status_code=403, detail="Agent does not own this job.")

        job.status = status_str.upper()
        if job.status == "RUNNING" and not job.started_at:
            job.started_at = datetime.now(timezone.utc)
        if job.status in ("COMPLETED", "FAILED", "CANCELLED"):
            job.completed_at = datetime.now(timezone.utc)
        if error:
            job.error = error

        db.commit()
        db.refresh(job)
        return job

    @classmethod
    def process_job_results(cls, db: Session, upload: JobResultUploadRequest) -> JobModel:
        """Validate, verify SHA-256 evidence integrity, generate custody chain, and ingest findings."""
        job = db.query(JobModel).filter(JobModel.job_id == upload.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=f"Job '{upload.job_id}' not found.")

        # Security check: verify agent ownership
        if job.agent_id != upload.agent_id:
            raise HTTPException(status_code=403, detail="Mismatched agent/job submission.")

        agent = db.query(AgentModel).filter(AgentModel.agent_id == upload.agent_id).first()
        hostname = agent.hostname if agent else "UNKNOWN"
        org_id = job.organization_id

        now = datetime.now(timezone.utc)

        # 1. Ingest Evidence Records & Verify SHA-256 Integrity
        for ev in upload.evidence_records:
            ev_id = ev.get("evidence_id") or f"EV-{uuid.uuid4().hex[:8].upper()}"
            ts_str = ev.get("timestamp")
            try:
                ev_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else now
            except Exception:
                ev_ts = now

            data_payload = ev.get("data")
            computed_hash = compute_canonical_evidence_hash(data_payload)
            provided_hash = ev.get("content_hash")

            integrity_verified = True
            if provided_hash and provided_hash != computed_hash:
                integrity_verified = False
                AuditService.log_security_event(
                    db=db,
                    event_type="INTEGRITY_FAILURE",
                    description=f"Evidence '{ev_id}' SHA-256 hash mismatch: expected {provided_hash}, computed {computed_hash}.",
                    severity="CRITICAL",
                    actor_id=upload.agent_id,
                    organization_id=org_id,
                    details={"evidence_id": ev_id, "computed": computed_hash, "provided": provided_hash},
                )

            existing_ev = db.query(CentralEvidenceModel).filter(CentralEvidenceModel.evidence_id == ev_id).first()
            if not existing_ev:
                evidence_entry = CentralEvidenceModel(
                    evidence_id=ev_id,
                    agent_id=upload.agent_id,
                    job_id=upload.job_id,
                    organization_id=org_id,
                    hostname=ev.get("hostname") or hostname,
                    timestamp=ev_ts,
                    operation=ev.get("operation") or "unknown",
                    collection_status=ev.get("collection_status") or "success",
                    data=data_payload,
                    content_hash=computed_hash,
                    hash_algorithm="SHA-256",
                    integrity_verified=integrity_verified,
                    collected_by_agent=upload.agent_id,
                    collected_at=ev_ts,
                    received_at=now,
                )
                db.add(evidence_entry)

                # Initialize Chain of Custody for new evidence
                # Step A: Collected by agent
                c_event1_id = f"CUST-{uuid.uuid4().hex[:8].upper()}"
                c1_hash = compute_event_hash("", ev_ts.isoformat(), upload.agent_id, "COLLECTED", ev_id)
                custody1 = EvidenceCustodyEventModel(
                    event_id=c_event1_id,
                    evidence_id=ev_id,
                    timestamp=ev_ts,
                    actor_type="AGENT",
                    actor_id=upload.agent_id,
                    action="COLLECTED",
                    previous_hash="",
                    event_hash=c1_hash,
                    metadata_json=json.dumps({"operation": ev.get("operation")}),
                )
                db.add(custody1)

                # Step B: Received by central server
                c_event2_id = f"CUST-{uuid.uuid4().hex[:8].upper()}"
                c2_hash = compute_event_hash(c1_hash, now.isoformat(), "central_server", "RECEIVED", ev_id)
                custody2 = EvidenceCustodyEventModel(
                    event_id=c_event2_id,
                    evidence_id=ev_id,
                    timestamp=now,
                    actor_type="SYSTEM",
                    actor_id="central_server",
                    action="RECEIVED",
                    previous_hash=c1_hash,
                    event_hash=c2_hash,
                    metadata_json=json.dumps({"integrity_verified": integrity_verified, "content_hash": computed_hash}),
                )
                db.add(custody2)

            else:
                existing_ev.job_id = upload.job_id
                existing_ev.data = data_payload
                existing_ev.content_hash = computed_hash
                existing_ev.integrity_verified = integrity_verified
                existing_ev.collection_status = ev.get("collection_status") or "success"

        # 2. Ingest Findings
        for f in upload.findings:
            f_id = f.get("finding_id") or f"THR-{uuid.uuid4().hex[:6].upper()}"
            ts_str = f.get("timestamp")
            try:
                f_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else now
            except Exception:
                f_ts = now

            existing_f = db.query(CentralFindingModel).filter(CentralFindingModel.finding_id == f_id).first()
            if not existing_f:
                finding_entry = CentralFindingModel(
                    finding_id=f_id,
                    agent_id=upload.agent_id,
                    job_id=upload.job_id,
                    organization_id=org_id,
                    rule_id=f.get("rule_id") or "UNKNOWN",
                    title=f.get("title") or "Unnamed Finding",
                    category=f.get("category") or "GENERAL",
                    severity=f.get("severity") or "MEDIUM",
                    confidence=float(f.get("confidence", 0.85)),
                    description=f.get("description"),
                    evidence_ids=f.get("evidence_ids") or [],
                    affected_object=f.get("affected_object"),
                    indicators=f.get("indicators") or {},
                    recommendation=f.get("recommendation"),
                    timestamp=f_ts,
                )
                db.add(finding_entry)
            else:
                existing_f.job_id = upload.job_id
                existing_f.severity = f.get("severity") or existing_f.severity

        # 3. Update Job Record & Audit
        job.status = upload.execution_status.upper()
        job.completed_at = now
        if upload.error:
            job.error = upload.error

        db.commit()
        db.refresh(job)

        # Automatically trigger forensic normalization & correlation
        try:
            from server.services.correlation_service import CorrelationService
            CorrelationService.run_for_organization(db, org_id)
        except Exception:
            pass

        AuditService.log(
            db=db,
            actor_type="AGENT",
            actor_id=upload.agent_id,
            action="JOB_COMPLETED",
            resource_type="JOB",
            resource_id=job.job_id,
            organization_id=org_id,
            result="SUCCESS",
            details={
                "status": job.status,
                "evidence_count": len(upload.evidence_records),
                "findings_count": len(upload.findings),
            },
        )

        return job
