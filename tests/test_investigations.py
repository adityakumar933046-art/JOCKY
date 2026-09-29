"""
Unit tests for JOCKY Investigation Management, Timeline, and Report Generation API.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
AGENT_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}


def test_investigation_lifecycle_and_timeline():
    # 1. Register Agent
    client.post(
        "/api/v1/agents/register",
        json={"agent_id": "AGT-INV-01", "hostname": "INVESTIGATED-HOST", "operating_system": "Windows"},
        headers=AGENT_HEADERS,
    )

    # 2. Create Job
    job_resp = client.post(
        "/api/v1/jobs",
        json={"name": "Forensic Triage", "agent_id": "AGT-INV-01", "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nREPORT \"r\""},
        headers=ANALYST_HEADERS,
    )
    job_id = job_resp.json()["job_id"]

    # 3. Upload Results (creates evidence & finding)
    client.post(
        f"/api/v1/jobs/{job_id}/results",
        json={
            "job_id": job_id,
            "agent_id": "AGT-INV-01",
            "evidence_records": [
                {
                    "evidence_id": "EV-INV-01",
                    "hostname": "INVESTIGATED-HOST",
                    "operation": "scan_processes",
                    "collection_status": "success",
                    "data": [],
                }
            ],
            "findings": [
                {
                    "finding_id": "THR-INV-01",
                    "rule_id": "PROC-001",
                    "title": "Suspicious Parent-Child Process",
                    "category": "PROCESS",
                    "severity": "HIGH",
                    "confidence": 0.90,
                    "evidence_ids": ["EV-INV-01"],
                }
            ],
            "execution_status": "COMPLETED",
        },
        headers=AGENT_HEADERS,
    )

    # 4. Create Investigation
    inv_payload = {
        "title": "Incident 2026-Alpha Host Triage",
        "description": "Investigation into suspicious process activity on INVESTIGATED-HOST.",
        "assigned_analyst": "lead_dfir_analyst",
        "agent_ids": ["AGT-INV-01"],
        "job_ids": [job_id],
        "evidence_ids": ["EV-INV-01"],
        "finding_ids": ["THR-INV-01"],
    }
    create_inv = client.post("/api/v1/investigations", json=inv_payload, headers=ANALYST_HEADERS)
    assert create_inv.status_code == 200
    inv = create_inv.json()
    inv_id = inv["investigation_id"]
    assert inv_id.startswith("INV-")
    assert inv["status"] == "OPEN"
    assert len(inv["agents"]) == 1
    assert len(inv["findings"]) == 1

    # 5. Update Investigation
    update_resp = client.patch(
        f"/api/v1/investigations/{inv_id}",
        json={"status": "IN_PROGRESS", "description": "Updated scope: triage verified."},
        headers=ANALYST_HEADERS,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "IN_PROGRESS"
    assert update_resp.json()["description"] == "Updated scope: triage verified."

    # 6. Generate Timeline
    timeline_resp = client.get(f"/api/v1/investigations/{inv_id}/timeline")
    assert timeline_resp.status_code == 200
    tl = timeline_resp.json()
    assert tl["investigation_id"] == inv_id
    assert tl["total_events"] >= 3
    event_types = [ev["event_type"] for ev in tl["events"]]
    assert "AGENT_REGISTERED" in event_types
    assert "JOB_CREATED" in event_types
    assert "FINDING_GENERATED" in event_types

    # 7. Generate Reports (HTML and JSON)
    html_resp = client.get(f"/api/v1/investigations/{inv_id}/report?format=html")
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
    assert "JOCKY Forensic Investigation Report" in html_resp.text
    assert "Incident 2026-Alpha Host Triage" in html_resp.text

    json_resp = client.get(f"/api/v1/investigations/{inv_id}/report?format=json")
    assert json_resp.status_code == 200
    assert "timeline" in json_resp.json()
    assert "investigation" in json_resp.json()
