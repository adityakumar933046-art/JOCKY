"""
Unit tests for JOCKY Server Central Evidence API.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
AGENT_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}


import uuid

def _seed_job_and_evidence():
    ev_id = f"EV-TEST-{uuid.uuid4().hex[:6]}"
    client.post(
        "/api/v1/agents/register",
        json={"agent_id": "AGT-EVTEST", "hostname": "EV-HOST", "operating_system": "Windows"},
        headers=AGENT_HEADERS,
    )
    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Evidence Job", "agent_id": "AGT-EVTEST", "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nREPORT \"r\""},
        headers=ANALYST_HEADERS,
    )
    job_id = job_resp.json()["job_id"]

    client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": "AGT-EVTEST",
            "evidence_records": [
                {
                    "evidence_id": ev_id,
                    "hostname": "EV-HOST",
                    "operation": "scan_processes",
                    "collection_status": "success",
                    "data": [{"pid": 1234, "name": "explorer.exe"}],
                }
            ],
            "findings": [],
            "execution_status": "COMPLETED",
        },
        headers=AGENT_HEADERS,
    )
    return job_id, ev_id


def test_get_central_evidence_list():
    job_id, ev_id = _seed_job_and_evidence()
    resp = client.get(f"/api/v1/evidence?job_id={job_id}")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    assert items[0]["evidence_id"] == ev_id
    assert items[0]["operation"] == "scan_processes"


def test_get_central_evidence_by_id():
    job_id, ev_id = _seed_job_and_evidence()
    resp = client.get(f"/api/v1/evidence/{ev_id}")
    assert resp.status_code == 200
    item = resp.json()
    assert item["evidence_id"] == ev_id
    assert item["hostname"] == "EV-HOST"


def test_get_central_evidence_not_found():
    resp = client.get("/api/v1/evidence/EV-NONEXISTENT")
    assert resp.status_code == 404
