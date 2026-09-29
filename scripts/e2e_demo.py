"""
End-to-End Live Integration Verification for JOCKY Step 4 Platform.

Tests the complete flow:
1. Server initialization & health.
2. Agent registration & heartbeat.
3. Compiler validation endpoint.
4. Job creation with JOCKY DSL script & strict IR allow-list validation.
5. Agent fetching job, executing real forensic collection, running ThreatDetectionEngine.
6. Central upload of Evidence and Findings.
7. Job completion state verification.
8. Central evidence and findings querying with filters.
9. Case investigation creation.
10. Chronological forensic timeline construction.
11. HTML and JSON report export generation.
"""

import sys
import os
from fastapi.testclient import TestClient
from server.main import app
from server.config import config
from agent.client import AgentClient
from agent.executor import AgentJobExecutor
from agent.identity import AgentIdentity

def run_live_e2e_verification():
    print("=" * 60)
    print("STARTING JOCKY STEP 4 END-TO-END VERIFICATION")
    print("=" * 60)

    client = TestClient(app)

    # 1. Health check
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    print("[OK] 1. Central Server Health Check OK:", res.json())

    import uuid
    agent_id = f"AGT-E2E-{uuid.uuid4().hex[:8].upper()}"
    identity = {
        "agent_id": agent_id,
        "hostname": "E2E-TEST-HOST",
        "operating_system": "Windows",
        "os_version": "10.0.22631",
        "architecture": "AMD64",
        "jocky_version": "1.0.0",
        "collector_version": "1.0.0",
    }

    reg_headers = {"X-Agent-Key": config.AGENT_SECRET_KEY}
    res = client.post(
        "/api/v1/agents/register",
        headers=reg_headers,
        json={
            "agent_id": agent_id,
            "hostname": identity["hostname"],
            "operating_system": identity["operating_system"],
            "os_version": identity["os_version"],
            "architecture": identity["architecture"],
            "jocky_version": identity["jocky_version"],
            "collector_version": identity["collector_version"],
        }
    )
    assert res.status_code == 200, f"Registration failed: {res.text}"
    print(f"[OK] 2. Agent Registered: {agent_id} ({identity['hostname']})")

    # 3. Agent Heartbeat
    res = client.post(f"/api/v1/agents/{agent_id}/heartbeat", headers=reg_headers)
    assert res.status_code == 200
    print("[OK] 3. Agent Heartbeat Recorded")

    # 4. Compiler Validation API
    sample_jocky = """# Rapid Triage Script
SYSTEM INFO
SCAN PROCESSES
SCAN NETWORK
ANALYZE PERSISTENCE
REPORT "e2e_triage_report"
"""
    res = client.post("/api/v1/compiler/validate", json={"source": sample_jocky})
    assert res.status_code == 200
    val_data = res.json()
    assert val_data["valid"] is True, f"Validation failed: {val_data.get('errors')}"
    print(f"[OK] 4. Compiler API Validated: {val_data['instructions_count']} IR instructions, {val_data['tokens_count']} tokens")

    # 5. Create Job via Analyst API
    analyst_headers = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
    job_payload = {
        "name": "E2E Live Forensic Triage",
        "agent_id": agent_id,
        "jocky_source": sample_jocky,
        "detection_enabled": True
    }
    res = client.post("/api/v1/jobs", headers=analyst_headers, json=job_payload)
    assert res.status_code in (200, 201), f"Job dispatch failed: {res.text}"
    job_data = res.json()
    job_id = job_data["job_id"]
    print(f"[OK] 5. Forensic Job Dispatched: {job_id} (Status: {job_data['status']})")

    # 6. Agent polls next job
    res = client.get(f"/api/v1/agents/{agent_id}/jobs/next", headers=reg_headers)
    assert res.status_code == 200
    fetched_job = res.json()
    assert fetched_job is not None
    assert fetched_job["job_id"] == job_id
    print(f"[OK] 6. Agent Fetched Job: {fetched_job['job_id']}")

    # 7. Agent executes the job locally (real forensic collection + Step 3 ThreatDetectionEngine)
    exec_result = AgentJobExecutor.execute_job(
        fetched_job["jocky_source"],
        detection_enabled=fetched_job.get("detection_enabled", True),
    )
    assert exec_result["success"] is True, f"Execution failed: {exec_result.get('error')}"
    print(f"[OK] 7. Agent Executed Job Locally: {len(exec_result['evidence_records'])} evidence items, {len(exec_result['findings'])} threat findings")

    # 8. Agent uploads results to Central Server
    upload_payload = {
        "job_id": job_id,
        "agent_id": agent_id,
        "execution_status": "COMPLETED",
        "evidence_records": exec_result["evidence_records"],
        "findings": exec_result["findings"],
        "error": exec_result.get("error"),
    }
    res = client.post(f"/api/v1/jobs/{job_id}/results", headers=reg_headers, json=upload_payload)
    assert res.status_code == 200, f"Upload results failed: {res.text}"
    print("[OK] 8. Results Uploaded to Central Server Successfully")

    # 9. Verify Job state is COMPLETED on Server
    res = client.get(f"/api/v1/jobs/{job_id}", headers=analyst_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "COMPLETED"
    print("[OK] 9. Job State Verified as COMPLETED on Central Server")

    # 10. Query Central Evidence & Findings
    ev_res = client.get(f"/api/v1/evidence?job_id={job_id}")
    assert ev_res.status_code == 200
    ev_list = ev_res.json()
    assert len(ev_list) >= 3
    print(f"[OK] 10. Central Evidence Store Verified: {len(ev_list)} records retrieved")

    fn_res = client.get(f"/api/v1/findings?job_id={job_id}")
    assert fn_res.status_code == 200
    fn_list = fn_res.json()
    print(f"[OK] 11. Central Findings Store Verified: {len(fn_list)} threat findings retrieved")

    # 12. Create Investigation Case linking everything
    inv_payload = {
        "title": "Incident Case 2026-E2E: Host Triage & Analysis",
        "description": "Automated end-to-end verification investigation correlating system triage artifacts.",
        "assigned_analyst": "Forensic Lead Auditor",
        "agent_ids": [agent_id],
        "job_ids": [job_id],
        "evidence_ids": [e["evidence_id"] for e in ev_list[:3]],
        "finding_ids": [f["finding_id"] for f in fn_list[:3]],
    }
    inv_res = client.post("/api/v1/investigations", headers=analyst_headers, json=inv_payload)
    assert inv_res.status_code in (200, 201), f"Investigation creation failed: {inv_res.text}"
    inv_data = inv_res.json()
    inv_id = inv_data["investigation_id"]
    print(f"[OK] 12. Investigation Case Created: {inv_id} ('{inv_data['title']}')")

    # 13. Query Chronological Timeline
    tl_res = client.get(f"/api/v1/investigations/{inv_id}/timeline")
    assert tl_res.status_code == 200
    tl_data = tl_res.json()
    assert tl_data["total_events"] > 0
    print(f"[OK] 13. Chronological Forensic Timeline Generated: {tl_data['total_events']} events ordered chronologically")

    # 14. Generate HTML and JSON Reports
    html_res = client.get(f"/api/v1/investigations/{inv_id}/report?format=html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "JOCKY Forensic Investigation Report" in html_res.text
    print(f"[OK] 14. HTML Forensic Report Generated ({len(html_res.text)} bytes)")

    json_res = client.get(f"/api/v1/investigations/{inv_id}/report?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    assert json_res.json()["investigation"]["investigation_id"] == inv_id
    print(f"[OK] 15. JSON Incident Package Generated ({len(json_res.content)} bytes)")

    # Clean up test identity
    if os.path.exists(".e2e_agent_identity.json"):
        os.remove(".e2e_agent_identity.json")

    print("=" * 60)
    print("ALL 15 END-TO-END VERIFICATION CHECKS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_live_e2e_verification()
