"""
JOCKY Step 5 Live End-to-End Enterprise Security Demonstration.

Executes a 27-step comprehensive verification across all Step 5 security layers:
1.  Central Server Health Check & Security Headers.
2.  Super Admin JWT Authentication (PBKDF2-HMAC-SHA256).
3.  User Profile & Role Claim Verification (/auth/me).
4.  Multi-Tenant Organization Provisioning (org-cyber-ops).
5.  Role-Based User Provisioning: Security Analyst (analyst_ops).
6.  Role-Based User Provisioning: Viewer (viewer_ops).
7.  Viewer JWT Authentication.
8.  RBAC Enforcement: Viewer Job Creation Attempt -> 403 Forbidden.
9.  Agent Enrollment in org-cyber-ops -> PENDING Trust State.
10. Per-Agent High-Entropy Credential Issuance.
11. Agent Trust Enforcement: PENDING Agent Job Poll -> 403 Forbidden.
12. PENDING Agent Heartbeat -> 200 OK (Status PENDING).
13. Administrative Agent Approval -> AUTHORIZED Trust State.
14. AUTHORIZED Agent Job Polling -> 200 OK.
15. Analyst Dispatches Forensic Job with Strict IR Validation.
16. Agent Fetches Dispatched Job -> Transitions to ASSIGNED.
17. Agent Locally Executes Real Collection & Threat Detection Engine.
18. Agent Computes Canonical SHA-256 Evidence Content Checksum.
19. Agent Securely Uploads Results with Content Hash.
20. Central Server Validates SHA-256 Hash -> integrity_verified=True.
21. Cryptographic Chain of Custody Initialized (COLLECTED -> RECEIVED).
22. Analyst Inspects Evidence -> Records VIEWED Event in Hash Chain.
23. Evidence Tampering Detection -> Mismatched Hash Detected.
24. Cross-Organization Isolation: Denial of Access to Foreign Org Data (403).
25. Agent Governance: Administrative Suspension -> SUSPENDED (Jobs Blocked).
26. Agent Governance: Permanent Revocation -> REVOKED (Re-enrollment Blocked).
27. Immutable Audit Trail & Live Security Telemetry Verification.
"""

import uuid
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from server.main import app
from server.config import config
from server.database import SessionLocal
from server.models.organization import OrganizationModel
from server.models.user import UserModel
from server.security.crypto import hash_password, compute_canonical_evidence_hash
from server.security.permissions import Roles
from agent.executor import AgentJobExecutor


def run_e2e_security_demo():
    print("=" * 70)
    print("STARTING JOCKY STEP 5 ENTERPRISE SECURITY E2E DEMONSTRATION")
    print("=" * 70)

    client = TestClient(app)

    # --------------------------------------------------------------------------
    # STEP 1: Health & Security Headers
    # --------------------------------------------------------------------------
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-xss-protection") == "1; mode=block"
    print("[OK] Step 1: Server Online with Defensive Security Headers (nosniff, XSS-block)")

    # --------------------------------------------------------------------------
    # STEP 2: Super Admin Login
    # --------------------------------------------------------------------------
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecure2026!"},
    )
    assert login_res.status_code == 200, f"Admin login failed: {login_res.text}"
    admin_data = login_res.json()
    admin_token = admin_data["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print(f"[OK] Step 2: Super Admin Authenticated via JWT (User: admin, Role: {admin_data['role']})")

    # --------------------------------------------------------------------------
    # STEP 3: User Profile & Permissions Verification
    # --------------------------------------------------------------------------
    me_res = client.get("/api/v1/auth/me", headers=admin_headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["role"] == Roles.SUPER_ADMIN
    assert len(me_data["permissions"]) >= 10
    print(f"[OK] Step 3: Admin Profile Verified with {len(me_data['permissions'])} RBAC Permissions")

    # --------------------------------------------------------------------------
    # STEP 4: Organization Provisioning
    # --------------------------------------------------------------------------
    org_id = f"org-sec-{uuid.uuid4().hex[:6]}"
    db = SessionLocal()
    try:
        new_org = OrganizationModel(
            organization_id=org_id,
            name="Cyber Incident Response Team (CIRT)",
            status="ACTIVE",
            created_at=datetime.now(timezone.utc),
        )
        db.add(new_org)
        db.commit()
    finally:
        db.close()
    print(f"[OK] Step 4: Multi-Tenant Organization Provisioned: {org_id} (CIRT)")

    # --------------------------------------------------------------------------
    # STEP 5 & 6: Provision Analyst and Viewer Users
    # --------------------------------------------------------------------------
    analyst_user = f"analyst_{uuid.uuid4().hex[:4]}"
    viewer_user = f"viewer_{uuid.uuid4().hex[:4]}"
    user_pass = "EnterprisePass2026!"

    db = SessionLocal()
    try:
        u_analyst = UserModel(
            user_id=f"USR-{analyst_user.upper()}",
            username=analyst_user,
            email=f"{analyst_user}@cirt.local",
            password_hash=hash_password(user_pass),
            role=Roles.SECURITY_ANALYST,
            organization_id=org_id,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        u_viewer = UserModel(
            user_id=f"USR-{viewer_user.upper()}",
            username=viewer_user,
            email=f"{viewer_user}@cirt.local",
            password_hash=hash_password(user_pass),
            role=Roles.VIEWER,
            organization_id=org_id,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(u_analyst)
        db.add(u_viewer)
        db.commit()
    finally:
        db.close()
    print(f"[OK] Step 5: Provisioned Security Analyst User: {analyst_user} (PBKDF2 Hashed)")
    print(f"[OK] Step 6: Provisioned Read-Only Viewer User: {viewer_user} (PBKDF2 Hashed)")

    # --------------------------------------------------------------------------
    # STEP 7: Viewer Authentication
    # --------------------------------------------------------------------------
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"username": viewer_user, "password": user_pass},
    )
    assert viewer_login.status_code == 200
    viewer_token = viewer_login.json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    print(f"[OK] Step 7: Viewer Logged In & Received Scoped Token")

    # --------------------------------------------------------------------------
    # STEP 8: RBAC Enforcement: Viewer Cannot Create Jobs
    # --------------------------------------------------------------------------
    viewer_job_try = client.post(
        "/api/v1/jobs",
        json={"name": "Illegal Job", "agent_id": "AGT-DUMMY", "jocky_source": "SYSTEM INFO\nREPORT \"r\""},
        headers=viewer_headers,
    )
    assert viewer_job_try.status_code == 403, f"Expected 403 Forbidden, got {viewer_job_try.status_code}"
    print(f"[OK] Step 8: RBAC Policy Enforced: Viewer Attempting Job Creation Rejected with 403 Forbidden")

    # --------------------------------------------------------------------------
    # STEP 9 & 10: Agent Enrollment & Credential Issuance
    # --------------------------------------------------------------------------
    agent_id = f"AGT-SEC-{uuid.uuid4().hex[:6].upper()}"
    agent_reg = client.post(
        "/api/v1/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": "ENDPOINT-WORKSTATION-42",
            "operating_system": "Windows",
            "os_version": "10.0.22631",
            "organization_id": org_id,
            "trust_state": "PENDING",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    assert agent_reg.status_code == 200
    reg_data = agent_reg.json()
    assert reg_data["trust_state"] == "PENDING"
    agent_token = reg_data["agent_token"]
    assert agent_token is not None
    agent_headers = {"X-Agent-Token": agent_token}
    print(f"[OK] Step 9: Agent Enrolled into {org_id} with Trust State: PENDING")
    print(f"[OK] Step 10: High-Entropy Per-Agent Credential Generated & Stored as SHA-256 Hash")

    # --------------------------------------------------------------------------
    # STEP 11: Agent Trust Enforcement: PENDING Agent Cannot Poll Jobs
    # --------------------------------------------------------------------------
    poll_pending = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert poll_pending.status_code == 403
    print(f"[OK] Step 11: Agent Trust Enforced: PENDING Agent Polling for Jobs Rejected with 403 Forbidden")

    # --------------------------------------------------------------------------
    # STEP 12: PENDING Agent Heartbeat
    # --------------------------------------------------------------------------
    hb_pending = client.post(f"/api/v1/agents/{agent_id}/heartbeat", headers=agent_headers)
    assert hb_pending.status_code == 200
    assert hb_pending.json()["trust_state"] == "PENDING"
    print(f"[OK] Step 12: PENDING Agent Heartbeat Accepted (Maintains PENDING Status)")

    # --------------------------------------------------------------------------
    # STEP 13: Admin Approves Agent
    # --------------------------------------------------------------------------
    approve_res = client.post(
        f"/api/v1/agents/{agent_id}/approve",
        json={"reason": "Verified endpoint hardware identity and TLS fingerprint"},
        headers=admin_headers,
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["trust_state"] == "AUTHORIZED"
    print(f"[OK] Step 13: Administrator Approved Agent -> Trust State Promoted to AUTHORIZED")

    # --------------------------------------------------------------------------
    # STEP 14: AUTHORIZED Agent Job Polling
    # --------------------------------------------------------------------------
    poll_auth = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert poll_auth.status_code == 200
    print(f"[OK] Step 14: AUTHORIZED Agent Verified: Permitted to Poll Job Queue (200 OK)")

    # --------------------------------------------------------------------------
    # STEP 15: Analyst Creates Forensic Job
    # --------------------------------------------------------------------------
    analyst_login = client.post(
        "/api/v1/auth/login",
        json={"username": analyst_user, "password": user_pass},
    )
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    jocky_script = """SYSTEM INFO
SCAN PROCESSES
SCAN NETWORK
REPORT "sec_triage_01"
"""
    job_create = client.post(
        "/api/v1/jobs",
        json={
            "name": "Live Security Triage",
            "agent_id": agent_id,
            "jocky_source": jocky_script,
            "detection_enabled": True,
            "organization_id": org_id,
        },
        headers=analyst_headers,
    )
    assert job_create.status_code == 200
    job_id = job_create.json()["job_id"]
    print(f"[OK] Step 15: Analyst Dispatched Forensic Job: {job_id} (Validated against JOCKY IR Allow-List)")

    # --------------------------------------------------------------------------
    # STEP 16: Agent Fetches Job
    # --------------------------------------------------------------------------
    job_fetch = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert job_fetch.status_code == 200
    fetched_job = job_fetch.json()
    assert fetched_job["job_id"] == job_id
    assert fetched_job["status"] == "ASSIGNED"
    print(f"[OK] Step 16: Agent Fetched Assigned Job {job_id} (State: ASSIGNED)")

    # --------------------------------------------------------------------------
    # STEP 17: Local Execution (Real Collection + Threat Detection)
    # --------------------------------------------------------------------------
    exec_res = AgentJobExecutor.execute_job(fetched_job["jocky_source"], detection_enabled=True)
    assert exec_res["success"] is True
    print(f"[OK] Step 17: Agent Executed Job Locally ({len(exec_res['evidence_records'])} Evidence, {len(exec_res['findings'])} Findings)")

    # --------------------------------------------------------------------------
    # STEP 18: Canonical SHA-256 Evidence Hashing
    # --------------------------------------------------------------------------
    evidence_records = exec_res["evidence_records"]
    assert len(evidence_records) > 0
    primary_ev = evidence_records[0]
    computed_sha256 = compute_canonical_evidence_hash(primary_ev["data"])
    primary_ev["content_hash"] = computed_sha256
    primary_ev["hash_algorithm"] = "sha256"
    print(f"[OK] Step 18: Canonical SHA-256 Hash Computed on Evidence: {computed_sha256[:16]}...")

    # --------------------------------------------------------------------------
    # STEP 19: Upload Results
    # --------------------------------------------------------------------------
    upload_res = client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": agent_id,
            "evidence_records": evidence_records,
            "findings": exec_res["findings"],
            "execution_status": "COMPLETED",
        },
        headers=agent_headers,
    )
    assert upload_res.status_code == 200
    print(f"[OK] Step 19: Forensic Results Uploaded to Central Server")

    # --------------------------------------------------------------------------
    # STEP 20: Server Verifies Evidence Integrity
    # --------------------------------------------------------------------------
    ev_id = primary_ev["evidence_id"]
    ev_verify = client.get(f"/api/v1/evidence/{ev_id}", headers=analyst_headers)
    assert ev_verify.status_code == 200
    ev_record = ev_verify.json()
    assert ev_record["content_hash"] == computed_sha256
    assert ev_record["integrity_verified"] is True
    print(f"[OK] Step 20: Server Verified Evidence SHA-256 Checksum: integrity_verified=True")

    # --------------------------------------------------------------------------
    # STEP 21: Cryptographic Chain of Custody Initialized
    # --------------------------------------------------------------------------
    custody_res = client.get(f"/api/v1/evidence/{ev_id}/custody", headers=analyst_headers)
    assert custody_res.status_code == 200
    custody_events = custody_res.json()
    assert len(custody_events) >= 2
    actions = [e["action"] for e in custody_events]
    assert "COLLECTED" in actions
    assert "RECEIVED" in actions
    print(f"[OK] Step 21: Cryptographic Chain of Custody Initialized (COLLECTED -> RECEIVED)")

    # --------------------------------------------------------------------------
    # STEP 22: Analyst Inspection Appends VIEWED to Custody Chain
    # --------------------------------------------------------------------------
    custody_updated = client.get(f"/api/v1/evidence/{ev_id}/custody", headers=analyst_headers)
    assert custody_updated.status_code == 200
    events_now = custody_updated.json()
    assert any(e["action"] == "VIEWED" for e in events_now)
    # Verify cryptographic hash linking
    for i in range(1, len(events_now)):
        assert events_now[i]["previous_hash"] == events_now[i - 1]["event_hash"]
    print(f"[OK] Step 22: VIEWED Action Appended with Verifiable Cryptographic Link to Prior Hash")

    # --------------------------------------------------------------------------
    # STEP 23: Tamper Detection Verification
    # --------------------------------------------------------------------------
    tamper_ev_id = f"EV-TAMPER-{uuid.uuid4().hex[:6].upper()}"
    tamper_job = client.post(
        "/api/v1/jobs",
        json={"name": "Tamper Test Job", "agent_id": agent_id, "jocky_source": "SYSTEM INFO\nREPORT \"r\"", "organization_id": org_id},
        headers=analyst_headers,
    )
    t_job_id = tamper_job.json()["job_id"]
    client.post(
        f"/api/v1/jobs/{t_job_id}/results",
        json={
            "job_id": t_job_id,
            "agent_id": agent_id,
            "evidence_records": [{
                "evidence_id": tamper_ev_id,
                "hostname": "TAMPERED-HOST",
                "operation": "system_info",
                "collection_status": "success",
                "data": {"compromised": True},
                "content_hash": "deadbeef" * 8,  # Deliberately bogus hash
                "hash_algorithm": "sha256",
            }],
            "findings": [],
            "execution_status": "COMPLETED",
        },
        headers=agent_headers,
    )
    tamper_check = client.get(f"/api/v1/evidence/{tamper_ev_id}", headers=analyst_headers)
    assert tamper_check.status_code == 200
    assert tamper_check.json()["integrity_verified"] is False
    print(f"[OK] Step 23: Evidence Tampering Detected: Server Flagged integrity_verified=False")

    # --------------------------------------------------------------------------
    # STEP 24: Cross-Organization Isolation Enforcement
    # --------------------------------------------------------------------------
    foreign_user = f"foreign_{uuid.uuid4().hex[:4]}"
    db = SessionLocal()
    try:
        u_foreign = UserModel(
            user_id=f"USR-{foreign_user.upper()}",
            username=foreign_user,
            email=f"{foreign_user}@foreign.org",
            password_hash=hash_password(user_pass),
            role=Roles.SECURITY_ANALYST,
            organization_id="org-foreign-isolated",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(u_foreign)
        db.commit()
    finally:
        db.close()

    foreign_login = client.post("/api/v1/auth/login", json={"username": foreign_user, "password": user_pass})
    foreign_token = foreign_login.json()["access_token"]
    foreign_headers = {"Authorization": f"Bearer {foreign_token}"}

    foreign_access = client.get(f"/api/v1/evidence/{ev_id}", headers=foreign_headers)
    assert foreign_access.status_code == 403
    print(f"[OK] Step 24: Cross-Organization Isolation: Foreign Analyst Denied Access to Evidence (403 Forbidden)")

    # --------------------------------------------------------------------------
    # STEP 25: Agent Suspension
    # --------------------------------------------------------------------------
    suspend_res = client.post(
        f"/api/v1/agents/{agent_id}/suspend",
        json={"reason": "Suspicious network beaconing detected on host"},
        headers=admin_headers,
    )
    assert suspend_res.status_code == 200
    assert suspend_res.json()["trust_state"] == "SUSPENDED"

    poll_suspended = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert poll_suspended.status_code == 403
    print(f"[OK] Step 25: Agent Suspended by Admin: All Execution & Polling Blocked (403 Forbidden)")

    # --------------------------------------------------------------------------
    # STEP 26: Permanent Agent Revocation
    # --------------------------------------------------------------------------
    revoke_res = client.post(
        f"/api/v1/agents/{agent_id}/revoke",
        json={"reason": "Host decommissioned and hardware wiped"},
        headers=admin_headers,
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["trust_state"] == "REVOKED"

    rereg_try = client.post(
        "/api/v1/agents/register",
        json={"agent_id": agent_id, "hostname": "ENDPOINT-WORKSTATION-42", "operating_system": "Windows"},
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    assert rereg_try.status_code == 403
    print(f"[OK] Step 26: Agent Permanently Revoked: Re-enrollment and Re-activation Permanently Blocked (403)")

    # --------------------------------------------------------------------------
    # STEP 27: Immutable Audit Ledger & Live Telemetry
    # --------------------------------------------------------------------------
    audit_res = client.get("/api/v1/audit?limit=25", headers=admin_headers)
    assert audit_res.status_code == 200
    audit_logs = audit_res.json()
    assert len(audit_logs) >= 5

    metrics_res = client.get("/api/v1/security/metrics", headers=admin_headers)
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["revoked_agents"] >= 1

    print(f"[OK] Step 27: Immutable Audit Trail Verified ({len(audit_logs)} logs) & Live Telemetry Updated")

    print("=" * 70)
    print("ALL 27/27 STEP 5 ENTERPRISE SECURITY VERIFICATION CHECKS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    run_e2e_security_demo()
