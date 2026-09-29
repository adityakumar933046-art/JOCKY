"""
JOCKY Investigation and Timeline Service.
Coordinates case management, chronological timeline generation, multi-tenancy,
and forensic report exports.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException

from server.models.investigation import InvestigationModel
from server.models.agent import AgentModel
from server.models.job import JobModel
from server.models.evidence import CentralEvidenceModel
from server.models.finding import CentralFindingModel
from server.models.user import UserModel
from server.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationUpdateRequest,
    TimelineEvent,
    TimelineResponse,
)
from server.config import config
from server.security.audit_service import AuditService


class InvestigationService:
    @classmethod
    def create_investigation(
        cls,
        db: Session,
        req: InvestigationCreateRequest,
        user: Optional[UserModel] = None,
    ) -> InvestigationModel:
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        org_id = user.organization_id if user else (req.organization_id or config.DEFAULT_ORG_ID)

        inv = InvestigationModel(
            investigation_id=inv_id,
            title=req.title,
            description=req.description,
            assigned_analyst=req.assigned_analyst or (user.username if user else "analyst"),
            created_by=user.username if user else req.created_by,
            organization_id=org_id,
            status="OPEN",
            created_at=datetime.now(timezone.utc),
        )

        # Attach relations if provided
        if req.agent_ids:
            inv.agents = db.query(AgentModel).filter(AgentModel.agent_id.in_(req.agent_ids)).all()
        if req.job_ids:
            inv.jobs = db.query(JobModel).filter(JobModel.job_id.in_(req.job_ids)).all()
        if req.evidence_ids:
            inv.evidence = db.query(CentralEvidenceModel).filter(CentralEvidenceModel.evidence_id.in_(req.evidence_ids)).all()
        if req.finding_ids:
            inv.findings = db.query(CentralFindingModel).filter(CentralFindingModel.finding_id.in_(req.finding_ids)).all()

        db.add(inv)
        db.commit()
        db.refresh(inv)

        AuditService.log(
            db=db,
            actor_type="USER" if user else "SYSTEM",
            actor_id=user.user_id if user else "system",
            action="INVESTIGATION_CREATED",
            resource_type="INVESTIGATION",
            resource_id=inv.investigation_id,
            organization_id=inv.organization_id,
            result="SUCCESS",
            details={"title": inv.title, "assigned_analyst": inv.assigned_analyst},
        )

        return inv

    @classmethod
    def get_all(cls, db: Session, organization_id: Optional[str] = None) -> List[InvestigationModel]:
        query = db.query(InvestigationModel)
        if organization_id:
            query = query.filter(InvestigationModel.organization_id == organization_id)
        return query.order_by(InvestigationModel.created_at.desc()).all()

    @classmethod
    def get_by_id(cls, db: Session, inv_id: str) -> Optional[InvestigationModel]:
        return db.query(InvestigationModel).filter(InvestigationModel.investigation_id == inv_id).first()

    @classmethod
    def update_investigation(
        cls,
        db: Session,
        inv_id: str,
        req: InvestigationUpdateRequest,
        user: Optional[UserModel] = None,
    ) -> InvestigationModel:
        inv = cls.get_by_id(db, inv_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        if req.title is not None:
            inv.title = req.title
        if req.description is not None:
            inv.description = req.description
        if req.status is not None:
            inv.status = req.status.upper()
        if req.assigned_analyst is not None:
            inv.assigned_analyst = req.assigned_analyst

        if req.agent_ids is not None:
            inv.agents = db.query(AgentModel).filter(AgentModel.agent_id.in_(req.agent_ids)).all()
        if req.job_ids is not None:
            inv.jobs = db.query(JobModel).filter(JobModel.job_id.in_(req.job_ids)).all()
        if req.evidence_ids is not None:
            inv.evidence = db.query(CentralEvidenceModel).filter(CentralEvidenceModel.evidence_id.in_(req.evidence_ids)).all()
        if req.finding_ids is not None:
            inv.findings = db.query(CentralFindingModel).filter(CentralFindingModel.finding_id.in_(req.finding_ids)).all()

        inv.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(inv)

        AuditService.log(
            db=db,
            actor_type="USER" if user else "SYSTEM",
            actor_id=user.user_id if user else "system",
            action="INVESTIGATION_UPDATED",
            resource_type="INVESTIGATION",
            resource_id=inv.investigation_id,
            organization_id=inv.organization_id,
            result="SUCCESS",
            details={"status": inv.status, "assigned_analyst": inv.assigned_analyst},
        )

        return inv

    @classmethod
    def generate_timeline(cls, db: Session, inv_id: str) -> TimelineResponse:
        inv = cls.get_by_id(db, inv_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        events: List[TimelineEvent] = []

        # 1. Agent Registrations
        for agent in inv.agents:
            if agent.registered_at:
                events.append(
                    TimelineEvent(
                        timestamp=agent.registered_at,
                        event_type="AGENT_REGISTERED",
                        summary=f"System '{agent.hostname}' ({agent.operating_system}) enrolled into investigation scope.",
                        details={"agent_id": agent.agent_id, "hostname": agent.hostname, "os": agent.operating_system},
                    )
                )

        # 2. Jobs execution milestones
        for job in inv.jobs:
            if job.created_at:
                events.append(
                    TimelineEvent(
                        timestamp=job.created_at,
                        event_type="JOB_CREATED",
                        summary=f"Forensic job '{job.name}' ({job.job_id}) created for agent {job.agent_id}.",
                        details={"job_id": job.job_id, "name": job.name, "agent_id": job.agent_id},
                    )
                )
            if job.started_at:
                events.append(
                    TimelineEvent(
                        timestamp=job.started_at,
                        event_type="JOB_STARTED",
                        summary=f"Agent started executing forensic job '{job.name}'.",
                        details={"job_id": job.job_id},
                    )
                )
            if job.completed_at:
                events.append(
                    TimelineEvent(
                        timestamp=job.completed_at,
                        event_type="JOB_COMPLETED" if job.status == "COMPLETED" else "JOB_FAILED",
                        summary=f"Job '{job.name}' finished with status: {job.status}.",
                        details={"job_id": job.job_id, "status": job.status, "error": job.error},
                    )
                )

        # 3. Evidence Collections
        for ev in inv.evidence:
            if ev.timestamp:
                events.append(
                    TimelineEvent(
                        timestamp=ev.timestamp,
                        event_type="EVIDENCE_COLLECTED",
                        summary=f"Evidence artifact acquired: {ev.operation} from host '{ev.hostname}'.",
                        details={"evidence_id": ev.evidence_id, "operation": ev.operation, "status": ev.collection_status},
                    )
                )

        # 4. Findings Generated
        for f in inv.findings:
            if f.timestamp:
                events.append(
                    TimelineEvent(
                        timestamp=f.timestamp,
                        event_type="FINDING_GENERATED",
                        summary=f"[{f.severity}] Indicator detected: '{f.title}' ({f.rule_id}) on {f.affected_object}.",
                        details={"finding_id": f.finding_id, "severity": f.severity, "rule_id": f.rule_id},
                    )
                )

        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)

        return TimelineResponse(
            investigation_id=inv.investigation_id,
            title=inv.title,
            total_events=len(events),
            events=events,
        )

    @classmethod
    def generate_html_report(cls, db: Session, inv_id: str, user: Optional[UserModel] = None) -> str:
        inv = cls.get_by_id(db, inv_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        timeline = cls.generate_timeline(db, inv_id)

        findings_rows = ""
        for f in inv.findings:
            sev_color = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#d97706",
                "LOW": "#2563eb",
                "INFO": "#64748b",
            }.get(f.severity, "#64748b")
            findings_rows += f"""
            <tr>
                <td><span style="background:{sev_color}; color:#fff; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{f.severity}</span></td>
                <td>{f.rule_id}</td>
                <td><strong>{f.title}</strong><br><small>{f.description or ''}</small></td>
                <td><code>{f.affected_object or 'N/A'}</code></td>
                <td>{f.confidence:.2f}</td>
            </tr>
            """

        evidence_rows = ""
        for ev in inv.evidence:
            integ_badge = (
                '<span style="background:#ecfdf5; color:#047857; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px; border:1px solid #a7f3d0;">✓ SHA-256 VERIFIED</span>'
                if ev.integrity_verified
                else '<span style="background:#fef2f2; color:#b91c1c; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px; border:1px solid #fecaca;">✗ HASH MISMATCH</span>'
            )
            evidence_rows += f"""
            <tr>
                <td><strong>{ev.operation}</strong></td>
                <td>{ev.hostname}</td>
                <td><code style="font-size:11px;">{ev.content_hash or 'N/A'}</code></td>
                <td>{integ_badge}</td>
                <td>{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
            </tr>
            """

        timeline_items = ""
        for ev in timeline.events:
            timeline_items += f"""
            <div style="margin-bottom: 12px; padding-left: 14px; border-left: 3px solid #2563eb;">
                <span style="font-size:12px; color:#64748b;">{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</span><br>
                <strong>[{ev.event_type}]</strong> {ev.summary}
            </div>
            """

        generated_by_str = user.username if user else inv.assigned_analyst or "analyst"
        now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>JOCKY Investigation Report - {inv.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #0f172a; line-height: 1.5; }}
        h1, h2, h3 {{ color: #0f172a; }}
        .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; background: #f8fafc; padding: 15px; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 30px; font-size: 13px; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; }}
        .disclaimer {{ background: #eff6ff; border: 1px solid #bfdbfe; padding: 12px; border-radius: 6px; font-size: 13px; color: #1e40af; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>JOCKY Forensic Investigation Report</h1>
        <h3>{inv.title} ({inv.investigation_id})</h3>
        <p style="color:#64748b; font-size:13px; margin:0;">Organization: <strong>{inv.organization_id}</strong> | Generated by: <strong>{generated_by_str}</strong> on <strong>{now_utc}</strong></p>
    </div>

    <div class="meta-grid">
        <div><strong>Status:</strong><br>{inv.status}</div>
        <div><strong>Assigned Analyst:</strong><br>{inv.assigned_analyst or 'Unassigned'}</div>
        <div><strong>Created At:</strong><br>{inv.created_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
        <div><strong>Total Findings:</strong><br>{len(inv.findings)}</div>
    </div>

    <h2>Case Scope & Description</h2>
    <p>{inv.description or 'No investigation description provided.'}</p>

    <h2>Evidence Integrity & Cryptographic Checksums</h2>
    <table>
        <thead>
            <tr><th>Operation</th><th>Source Host</th><th>SHA-256 Content Hash</th><th>Integrity Status</th><th>Acquired At</th></tr>
        </thead>
        <tbody>
            {evidence_rows or '<tr><td colspan="5">No evidence artifacts attached to this investigation.</td></tr>'}
        </tbody>
    </table>

    <h2>Threat Findings</h2>
    <table>
        <thead>
            <tr><th>Severity</th><th>Rule</th><th>Title & Description</th><th>Affected Object</th><th>Confidence</th></tr>
        </thead>
        <tbody>
            {findings_rows or '<tr><td colspan="5">No findings attached.</td></tr>'}
        </tbody>
    </table>

    <h2>Forensic Investigation Timeline</h2>
    <div style="margin-top: 15px;">
        {timeline_items or '<p>No timeline events recorded.</p>'}
    </div>

    <div class="disclaimer">
        <strong>Forensic Integrity Notice:</strong> JOCKY findings represent observed technical indicators requiring analyst verification and do not constitute autonomous proof of compromise. All evidence was collected via authorized, read-only forensic collectors and validated against SHA-256 canonical checksums.
    </div>
</body>
</html>
"""
        AuditService.log(
            db=db,
            actor_type="USER" if user else "SYSTEM",
            actor_id=user.user_id if user else "system",
            action="REPORT_GENERATED",
            resource_type="REPORT",
            resource_id=inv.investigation_id,
            organization_id=inv.organization_id,
            result="SUCCESS",
            details={"investigation_id": inv.investigation_id, "format": "html"},
        )

        return html
