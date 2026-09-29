"""
Unit tests for JOCKY Server Job Management API.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
AGENT_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}


def _ensure_agent():
    client.post(
        "/api/v1/agents/register",
        json={
            "agent_id": "AGT-JOBTEST",
            "hostname": "JOB-WORKER-01",
            "operating_system": "Linux",
            "os_version": "6.1",
            "architecture": "x86_64",
        },
        headers=AGENT_HEADERS,
    )


def test_job_creation_valid():
    _ensure_agent()
    payload = {
        "name": "Process & Network Triage",
        "agent_id": "AGT-JOBTEST",
        "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nSCAN NETWORK\nREPORT \"triage_rep\"",
        "detection_enabled": True,
    }
    resp = client.post("/api/v1/jobs", json=payload, headers=ANALYST_HEADERS)
    assert resp.status_code == 200
    job = resp.json()
    assert job["job_id"].startswith("JOB-")
    assert job["status"] == "PENDING"
    assert job["agent_id"] == "AGT-JOBTEST"


def test_job_creation_invalid_jocky_rejected():
    _ensure_agent()
    payload = {
        "name": "Invalid Script Job",
        "agent_id": "AGT-JOBTEST",
        "jocky_source": "MALICIOUS OR UNKNOWN SYNTAX 123",
    }
    resp = client.post("/api/v1/jobs", json=payload, headers=ANALYST_HEADERS)
    assert resp.status_code == 400
    assert "JOCKY compilation failed" in resp.json()["detail"]


def test_job_creation_nonexistent_agent():
    payload = {
        "name": "Ghost Agent Job",
        "agent_id": "GHOST-AGENT-999",
        "jocky_source": "SYSTEM INFO\nREPORT \"rep\"",
    }
    resp = client.post("/api/v1/jobs", json=payload, headers=ANALYST_HEADERS)
    assert resp.status_code == 404


def test_job_assignment_and_execution_lifecycle():
    client.post(
        "/api/v1/agents/register",
        json={"agent_id": "AGT-LIFECYCLE", "hostname": "LIFECYCLE-HOST", "operating_system": "Windows"},
        headers=AGENT_HEADERS,
    )
    # 1. Create job
    create_resp = client.post(
        "/api/v1/jobs",
        json={
            "name": "Lifecycle Job",
            "agent_id": "AGT-LIFECYCLE",
            "jocky_source": "SYSTEM INFO\nREPORT \"rep\"",
        },
        headers=ANALYST_HEADERS,
    )
    job_id = create_resp.json()["job_id"]

    # 2. Agent fetches next job -> transitions to ASSIGNED
    fetch_resp = client.get("/api/v1/agents/AGT-LIFECYCLE/jobs/next", headers=AGENT_HEADERS)
    assert fetch_resp.status_code == 200
    assigned_job = fetch_resp.json()
    assert assigned_job["job_id"] == job_id
    assert assigned_job["status"] == "ASSIGNED"

    # 3. Agent updates status to RUNNING
    status_resp = client.post(
        f"/api/v1/jobs/{job_id}/status?agent_id=AGT-LIFECYCLE",
        json={"status": "RUNNING"},
        headers=AGENT_HEADERS,
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "RUNNING"

    # 4. Agent uploads results
    result_payload = {
        "job_id": job_id,
        "agent_id": "AGT-LIFECYCLE",
        "evidence_records": [
            {
                "evidence_id": "EV-JOB-01",
                "hostname": "LIFECYCLE-HOST",
                "operation": "system_info",
                "collection_status": "success",
                "data": {"kernel": "6.1"},
            }
        ],
        "findings": [
            {
                "finding_id": "THR-JOB-01",
                "rule_id": "PROC-001",
                "title": "Test Finding",
                "category": "PROCESS",
                "severity": "LOW",
                "confidence": 0.85,
                "evidence_ids": ["EV-JOB-01"],
            }
        ],
        "execution_status": "COMPLETED",
    }
    upload_resp = client.post(f"/api/v1/jobs/{job_id}/results", json=result_payload, headers=AGENT_HEADERS)
    assert upload_resp.status_code == 200
    assert upload_resp.json()["status"] == "COMPLETED"


def test_job_results_mismatched_agent_rejected():
    _ensure_agent()
    # Create job for AGT-JOBTEST
    create_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Mismatched Test", "agent_id": "AGT-JOBTEST", "jocky_source": "SYSTEM INFO\nREPORT \"rep\""},
        headers=ANALYST_HEADERS,
    )
    job_id = create_resp.json()["job_id"]

    # Try uploading with a different agent ID
    bad_payload = {
        "job_id": job_id,
        "agent_id": "AGT-ROGUE",
        "evidence_records": [],
        "findings": [],
        "execution_status": "COMPLETED",
    }
    upload_resp = client.post(f"/api/v1/jobs/{job_id}/results", json=bad_payload, headers=AGENT_HEADERS)
    assert upload_resp.status_code == 403
    assert "Mismatched agent/job submission" in upload_resp.json()["detail"]
