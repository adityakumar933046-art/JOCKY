"""
Unit tests for JOCKY Server Central Findings API.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
AGENT_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}


import uuid

def _seed_findings():
    f1_id = f"THR-TEST-1-{uuid.uuid4().hex[:6]}"
    f2_id = f"THR-TEST-2-{uuid.uuid4().hex[:6]}"

    client.post(
        "/api/v1/agents/register",
        json={"agent_id": "AGT-FINDTEST", "hostname": "FIND-HOST", "operating_system": "Linux"},
        headers=AGENT_HEADERS,
    )
    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Finding Job", "agent_id": "AGT-FINDTEST", "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nREPORT \"r\""},
        headers=ANALYST_HEADERS,
    )
    job_id = job_resp.json()["job_id"]

    client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": "AGT-FINDTEST",
            "evidence_records": [],
            "findings": [
                {
                    "finding_id": f1_id,
                    "rule_id": "PROC-001",
                    "title": "Suspicious Process Relationship",
                    "category": "PROCESS",
                    "severity": "HIGH",
                    "confidence": 0.91,
                    "description": "Child spawned by unexpected parent.",
                    "affected_object": "net.exe",
                },
                {
                    "finding_id": f2_id,
                    "rule_id": "NET-002",
                    "title": "Unusual Listening Port",
                    "category": "NETWORK",
                    "severity": "MEDIUM",
                    "confidence": 0.82,
                    "description": "Port 4444 listening.",
                    "affected_object": "Port 4444/TCP",
                },
            ],
            "execution_status": "COMPLETED",
        },
        headers=AGENT_HEADERS,
    )
    return job_id, f1_id, f2_id


def test_list_findings_and_filters():
    job_id, f1_id, f2_id = _seed_findings()
    # 1. All findings for job
    resp = client.get(f"/api/v1/findings?job_id={job_id}")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2

    # 2. Filter by severity=HIGH
    resp_high = client.get(f"/api/v1/findings?job_id={job_id}&severity=HIGH")
    assert resp_high.status_code == 200
    assert len(resp_high.json()) == 1
    assert resp_high.json()[0]["rule_id"] == "PROC-001"

    # 3. Filter by category=NETWORK
    resp_net = client.get(f"/api/v1/findings?job_id={job_id}&category=NETWORK")
    assert resp_net.status_code == 200
    assert len(resp_net.json()) == 1
    assert resp_net.json()[0]["finding_id"] == f2_id


def test_get_finding_by_id():
    job_id, f1_id, f2_id = _seed_findings()
    resp = client.get(f"/api/v1/findings/{f1_id}")
    assert resp.status_code == 200
    item = resp.json()
    assert item["finding_id"] == f1_id
    assert item["severity"] == "HIGH"
    assert item["rule_id"] == "PROC-001"


def test_get_finding_not_found():
    resp = client.get("/api/v1/findings/THR-NONEXISTENT")
    assert resp.status_code == 404
