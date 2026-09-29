"""
JOCKY Step 5 Enterprise Security Architecture Test Suite.

Verifies:
1. User Authentication (JWT, PBKDF2 password hashing, logout token revocation, account lockout policy).
2. Role-Based Access Control (RBAC 5-tier permission enforcement).
3. Multi-Tenant Organization Isolation.
4. Agent Trust Lifecycle (PENDING -> AUTHORIZED -> SUSPENDED -> REVOKED).
5. Evidence Integrity & Canonical SHA-256 Verification.
6. Cryptographically Linked Chain of Custody.
7. Immutable Audit Logging & Security Monitoring.
8. Rate Limiting Protection.
9. Configurable PBKDF2 Iterations and Production Secret Key Enforcement.
"""

import time
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from server.main import app
from server.config import config, ServerConfig
from server.database import SessionLocal
from server.models.user import UserModel
from server.models.organization import OrganizationModel
from server.models.agent import AgentModel
from server.models.evidence import CentralEvidenceModel
from server.security.crypto import hash_password, compute_evidence_hash, compute_custody_hash
from server.security.tokens import create_access_token, decode_access_token
from server.security.permissions import Roles
from server.security.rate_limiter import rate_limiter

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Reset in-memory rate limits and unlock default admin before each test run."""
    rate_limiter.reset()
    db = SessionLocal()
    try:
        admin = db.query(UserModel).filter(UserModel.username == "admin").first()
        if admin:
            admin.failed_login_attempts = 0
            admin.locked_until = None
            db.commit()
    finally:
        db.close()


def _get_admin_token() -> str:
    """Helper to log in as default Super Admin and obtain a valid JWT."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecure2026!"},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    return resp.json()["access_token"]


def _get_analyst_token() -> str:
    """Helper to log in as default Security Analyst."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "AnalystSecure2026!"},
    )
    assert resp.status_code == 200, f"Analyst login failed: {resp.text}"
    return resp.json()["access_token"]


def _seed_custom_user(username: str, role: str, org_id: str, password: str = "TestPass123!") -> UserModel:
    """Seed a test user with a specific role and organization (idempotent)."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            user = UserModel(
                user_id=f"USR-{username.upper()}",
                username=username,
                email=f"{username}@test.org",
                password_hash=hash_password(password),
                role=role,
                organization_id=org_id,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(user)
        else:
            user.password_hash = hash_password(password)
            user.failed_login_attempts = 0
            user.locked_until = None
            user.role = role
            user.organization_id = org_id
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _seed_custom_organization(org_id: str, name: str) -> OrganizationModel:
    """Seed a test organization."""
    db = SessionLocal()
    try:
        org = db.query(OrganizationModel).filter(OrganizationModel.organization_id == org_id).first()
        if not org:
            org = OrganizationModel(
                organization_id=org_id,
                name=name,
                status="ACTIVE",
                created_at=datetime.now(timezone.utc),
            )
            db.add(org)
            db.commit()
            db.refresh(org)
        return org
    finally:
        db.close()


# ==============================================================================
# 1. USER AUTHENTICATION & TOKEN LIFECYCLE
# ==============================================================================

def test_auth_login_success():
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecure2026!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["username"] == "admin"
    assert data["role"] == Roles.SUPER_ADMIN

    # Verify decoded token structure
    payload = decode_access_token(data["access_token"])
    assert payload["sub"] == data["user_id"]
    assert payload["username"] == "admin"
    assert payload["role"] == Roles.SUPER_ADMIN
    assert "jti" in payload
    assert "exp" in payload


def test_auth_login_invalid_password():
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


def test_auth_login_unknown_user():
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "unknown_ghost_user", "password": "SomePassword123!"},
    )
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


def test_auth_me_endpoint():
    token = _get_admin_token()
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "admin"
    assert len(data["permissions"]) > 0


def test_auth_logout_and_revocation():
    token = _get_admin_token()
    # Confirm token works
    resp1 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp1.status_code == 200

    # Logout
    logout_resp = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200

    # Token should now be revoked and rejected
    resp2 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp2.status_code == 401
    assert "revoked" in resp2.json()["detail"].lower()


def test_auth_account_lockout_policy():
    lockout_user = "test_lockout_target"
    _seed_custom_user(lockout_user, Roles.VIEWER, config.DEFAULT_ORG_ID, "GoodPass123!")

    # Attempt 5 consecutive failed logins
    for attempt in range(config.MAX_LOGIN_ATTEMPTS):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": lockout_user, "password": "BadPassword!"},
        )
        assert resp.status_code == 401

    # 6th attempt should be rejected due to account lockout
    resp_locked = client.post(
        "/api/v1/auth/login",
        json={"username": lockout_user, "password": "GoodPass123!"},
    )
    assert resp_locked.status_code == 401
    assert "locked" in resp_locked.json()["detail"].lower()


def test_auth_change_password():
    pwd_user = "test_pwd_user"
    _seed_custom_user(pwd_user, Roles.INVESTIGATOR, config.DEFAULT_ORG_ID, "InitialPass123!")

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": pwd_user, "password": "InitialPass123!"},
    )
    token = login_resp.json()["access_token"]

    # Change password
    chg_resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "InitialPass123!", "new_password": "NewSecurePass2026!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert chg_resp.status_code == 200

    # Old password fails
    resp_old = client.post(
        "/api/v1/auth/login",
        json={"username": pwd_user, "password": "InitialPass123!"},
    )
    assert resp_old.status_code == 401

    # New password succeeds
    resp_new = client.post(
        "/api/v1/auth/login",
        json={"username": pwd_user, "password": "NewSecurePass2026!"},
    )
    assert resp_new.status_code == 200


# ==============================================================================
# 2. ROLE-BASED ACCESS CONTROL (RBAC)
# ==============================================================================

def test_rbac_viewer_cannot_create_jobs():
    viewer_user = "test_viewer"
    _seed_custom_user(viewer_user, Roles.VIEWER, config.DEFAULT_ORG_ID, "ViewerPass123!")

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": viewer_user, "password": "ViewerPass123!"},
    )
    token = login_resp.json()["access_token"]

    # Viewer attempts job creation -> Forbidden (403)
    resp = client.post(
        "/api/v1/jobs",
        json={
            "name": "Unauthorized Viewer Job",
            "agent_id": "AGT-TEST01",
            "jocky_source": "SYSTEM INFO\nREPORT \"r\"",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]


def test_rbac_analyst_cannot_approve_agents():
    analyst_token = _get_analyst_token()

    # Analyst attempts to approve an agent -> Forbidden (403)
    resp = client.post(
        "/api/v1/agents/AGT-TEST01/approve",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]


def test_rbac_super_admin_can_approve_agents():
    admin_token = _get_admin_token()

    # Admin approves an agent -> Allowed (200)
    resp = client.post(
        "/api/v1/agents/AGT-TEST01/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["trust_state"] == "AUTHORIZED"


# ==============================================================================
# 3. MULTI-TENANT ORGANIZATION ISOLATION
# ==============================================================================

def test_organization_isolation_agent_access():
    _seed_custom_organization("org-alpha", "Alpha Defense Inc")
    _seed_custom_organization("org-beta", "Beta SOC")

    _seed_custom_user("alpha_admin", Roles.ORGANIZATION_ADMIN, "org-alpha", "AlphaAdmin123!")
    _seed_custom_user("beta_admin", Roles.ORGANIZATION_ADMIN, "org-beta", "BetaAdmin123!")

    # Register agent in org-alpha
    client.post(
        "/api/v1/agents/register",
        json={
            "agent_id": "AGT-ALPHA-01",
            "hostname": "ALPHA-HOST-01",
            "operating_system": "Windows",
            "organization_id": "org-alpha",
            "trust_state": "PENDING",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )

    # Beta admin logs in
    beta_login = client.post(
        "/api/v1/auth/login",
        json={"username": "beta_admin", "password": "BetaAdmin123!"},
    )
    beta_token = beta_login.json()["access_token"]

    # Beta admin attempts to access Alpha agent -> Forbidden (403)
    resp = client.get(
        "/api/v1/agents/AGT-ALPHA-01",
        headers={"Authorization": f"Bearer {beta_token}"},
    )
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]


# ==============================================================================
# 4. AGENT TRUST LIFECYCLE (PENDING -> AUTHORIZED -> SUSPENDED -> REVOKED)
# ==============================================================================

def test_agent_trust_lifecycle_complete():
    import uuid
    admin_token = _get_admin_token()
    agent_id = f"AGT-TRUST-{uuid.uuid4().hex[:8].upper()}"

    # 1. Registration in PENDING state
    reg_resp = client.post(
        "/api/v1/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": "TRUST-WORKER",
            "operating_system": "Windows",
            "trust_state": "PENDING",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["trust_state"] == "PENDING"
    per_agent_token = reg_data["agent_token"]
    assert per_agent_token is not None

    agent_headers = {"X-Agent-Token": per_agent_token}

    # 2. PENDING agent cannot receive jobs -> 403 Forbidden
    job_poll_pending = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert job_poll_pending.status_code == 403
    assert "Cannot receive jobs" in job_poll_pending.json()["detail"]

    # 3. Super Admin approves agent -> AUTHORIZED
    approve_resp = client.post(
        f"/api/v1/agents/{agent_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["trust_state"] == "AUTHORIZED"

    # 4. AUTHORIZED agent can poll jobs -> 200 OK (returns null if queue empty)
    job_poll_auth = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert job_poll_auth.status_code == 200

    # 5. Admin suspends agent -> SUSPENDED
    suspend_resp = client.post(
        f"/api/v1/agents/{agent_id}/suspend",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert suspend_resp.status_code == 200
    assert suspend_resp.json()["trust_state"] == "SUSPENDED"

    # 6. SUSPENDED agent cannot heartbeat or receive jobs -> 403 Forbidden
    hb_suspended = client.post(f"/api/v1/agents/{agent_id}/heartbeat", headers=agent_headers)
    assert hb_suspended.status_code == 403

    job_poll_suspended = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=agent_headers)
    assert job_poll_suspended.status_code == 403

    # 7. Admin revokes agent -> REVOKED (Permanent)
    revoke_resp = client.post(
        f"/api/v1/agents/{agent_id}/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["trust_state"] == "REVOKED"

    # 8. REVOKED agent cannot re-register -> 403 Forbidden
    rereg_resp = client.post(
        "/api/v1/agents/register",
        json={
            "agent_id": agent_id,
            "hostname": "TRUST-WORKER",
            "operating_system": "Windows",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    assert rereg_resp.status_code == 403
    assert "permanently revoked" in rereg_resp.json()["detail"].lower()

    # 9. Cannot approve a revoked agent -> 400 Bad Request
    reapprove_resp = client.post(
        f"/api/v1/agents/{agent_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert reapprove_resp.status_code == 400


# ==============================================================================
# 5. EVIDENCE INTEGRITY & SHA-256 VERIFICATION
# ==============================================================================

def test_evidence_integrity_sha256_canonical():
    admin_token = _get_admin_token()
    agent_id = "AGT-INT-01"

    # Register & approve agent
    client.post(
        "/api/v1/agents/register",
        json={"agent_id": agent_id, "hostname": "INT-HOST", "operating_system": "Windows"},
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    client.post(f"/api/v1/agents/{agent_id}/approve", headers={"Authorization": f"Bearer {admin_token}"})

    # Create Job
    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Integrity Job", "agent_id": agent_id, "jocky_source": "SYSTEM INFO\nREPORT \"r\""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    job_id = job_resp.json()["job_id"]

    raw_data = {"os": "Windows 11", "build": 22631, "arch": "x64"}
    expected_hash = compute_evidence_hash(raw_data)

    # Agent uploads valid results with matching SHA-256 hash
    results_resp = client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": agent_id,
            "evidence_records": [
                {
                    "evidence_id": "EV-INT-VALID-01",
                    "hostname": "INT-HOST",
                    "operation": "system_info",
                    "collection_status": "success",
                    "data": raw_data,
                    "content_hash": expected_hash,
                    "hash_algorithm": "sha256",
                }
            ],
            "findings": [],
            "execution_status": "COMPLETED",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    assert results_resp.status_code == 200

    # Verify central evidence store preserved the hash and integrity status
    ev_resp = client.get("/api/v1/evidence/EV-INT-VALID-01", headers={"Authorization": f"Bearer {admin_token}"})
    assert ev_resp.status_code == 200
    ev_data = ev_resp.json()
    assert ev_data["content_hash"] == expected_hash
    assert ev_data["integrity_verified"] is True


def test_evidence_integrity_tamper_detection():
    admin_token = _get_admin_token()
    agent_id = "AGT-TAMPER-01"

    client.post(
        "/api/v1/agents/register",
        json={"agent_id": agent_id, "hostname": "TAMPER-HOST", "operating_system": "Windows"},
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    client.post(f"/api/v1/agents/{agent_id}/approve", headers={"Authorization": f"Bearer {admin_token}"})

    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Tamper Test Job", "agent_id": agent_id, "jocky_source": "SYSTEM INFO\nREPORT \"r\""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    job_id = job_resp.json()["job_id"]

    raw_data = {"tampered": True}
    bogus_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Agent uploads results with mismatched hash -> triggers integrity alert
    client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": agent_id,
            "evidence_records": [
                {
                    "evidence_id": "EV-INT-TAMPERED-01",
                    "hostname": "TAMPER-HOST",
                    "operation": "system_info",
                    "collection_status": "success",
                    "data": raw_data,
                    "content_hash": bogus_hash,
                    "hash_algorithm": "sha256",
                }
            ],
            "findings": [],
            "execution_status": "COMPLETED",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )

    # Check evidence record marked as integrity failure
    ev_resp = client.get("/api/v1/evidence/EV-INT-TAMPERED-01", headers={"Authorization": f"Bearer {admin_token}"})
    assert ev_resp.status_code == 200
    ev_data = ev_resp.json()
    assert ev_data["integrity_verified"] is False


# ==============================================================================
# 6. CHAIN OF CUSTODY & AUDIT VERIFICATION
# ==============================================================================

def test_chain_of_custody_tracking():
    import uuid
    admin_token = _get_admin_token()
    ev_id = f"EV-CUST-{uuid.uuid4().hex[:8].upper()}"
    agent_id = "AGT-CUST-WORKER"

    # Register & approve agent
    client.post(
        "/api/v1/agents/register",
        json={"agent_id": agent_id, "hostname": "CUST-HOST", "operating_system": "Linux"},
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )
    client.post(f"/api/v1/agents/{agent_id}/approve", headers={"Authorization": f"Bearer {admin_token}"})

    # Create Job
    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Custody Job", "agent_id": agent_id, "jocky_source": "SYSTEM INFO\nREPORT \"r\""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    job_id = job_resp.json()["job_id"]

    # Upload evidence
    client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": agent_id,
            "evidence_records": [
                {
                    "evidence_id": ev_id,
                    "hostname": "CUST-HOST",
                    "operation": "system_info",
                    "collection_status": "success",
                    "data": {"kernel": "6.5"},
                }
            ],
            "findings": [],
            "execution_status": "COMPLETED",
        },
        headers={"X-Agent-Key": config.AGENT_SECRET_KEY},
    )

    # Analyst views evidence (adds VIEWED event to custody chain)
    client.get(f"/api/v1/evidence/{ev_id}", headers={"Authorization": f"Bearer {admin_token}"})

    # Query custody events
    custody_resp = client.get(
        f"/api/v1/evidence/{ev_id}/custody",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert custody_resp.status_code == 200
    events = custody_resp.json()
    assert len(events) >= 3
    actions = [ev["action"] for ev in events]
    assert "COLLECTED" in actions
    assert "RECEIVED" in actions
    assert "VIEWED" in actions

    # Verify cryptographic chaining
    for i in range(1, len(events)):
        prev = events[i - 1]
        curr = events[i]
        assert curr["previous_hash"] == prev["event_hash"]


def test_immutable_audit_log_querying():
    admin_token = _get_admin_token()

    audit_resp = client.get("/api/v1/audit?limit=20", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) > 0
    actions = [l["action"] for l in logs]
    assert any("LOGIN" in a or "AGENT" in a for a in actions)


def test_security_metrics_endpoint():
    admin_token = _get_admin_token()

    metrics_resp = client.get("/api/v1/security/metrics", headers={"Authorization": f"Bearer {admin_token}"})
    assert metrics_resp.status_code == 200
    m = metrics_resp.json()
    assert "authorized_agents" in m
    assert "authentication_failures" in m


# ==============================================================================
# 7. RATE LIMITING
# ==============================================================================

def test_rate_limiter_enforcement():
    # Attempt rapid repeated logins from an IP
    # Limiter allows 10 logins per 60s
    for i in range(10):
        client.post("/api/v1/auth/login", json={"username": "probe_user", "password": "WrongPassword"})

    # 11th request triggers 429
    blocked_resp = client.post("/api/v1/auth/login", json={"username": "probe_user", "password": "WrongPassword"})
    assert blocked_resp.status_code == 429
    assert "Rate limit exceeded" in blocked_resp.json()["detail"]


# ==============================================================================
# 8. PRODUCTION CONFIGURATION DEFENSES
# ==============================================================================

def test_production_secret_key_validation():
    # Verify that in production mode, missing or short secret key raises ValueError
    import os
    orig_env = os.environ.get("JOCKY_ENV")
    orig_secret = os.environ.get("JOCKY_SECRET_KEY")

    try:
        os.environ["JOCKY_ENV"] = "production"
        os.environ["JOCKY_SECRET_KEY"] = "short-key"

        with pytest.raises(ValueError, match="FATAL CONFIGURATION ERROR"):
            # Instantiating ServerConfig under production with short key must fail
            ServerConfig()
    finally:
        if orig_env:
            os.environ["JOCKY_ENV"] = orig_env
        else:
            os.environ.pop("JOCKY_ENV", None)
        if orig_secret:
            os.environ["JOCKY_SECRET_KEY"] = orig_secret
        else:
            os.environ.pop("JOCKY_SECRET_KEY", None)


def test_configurable_pbkdf2_iterations():
    assert config.PBKDF2_ITERATIONS >= 100000
