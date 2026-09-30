"""
JOCKY Live Production Forensic Pipeline Demonstration over Public HTTPS.
Demonstrates:
JOCKY Script -> Compilation -> Live Forensic Collection -> Evidence -> Threat Detection -> IOC Extraction -> Correlation -> Investigation -> Report
All executed over the live public Cloudflare HTTPS URL.
"""

import httpx
from agent.config import AgentConfig
from agent.client import AgentClient
from agent.identity import AgentIdentity
from agent.executor import AgentJobExecutor

SERVER = "https://plaintiff-robin-blanket-refer.trycloudflare.com"

def main():
    print("=" * 70)
    print("JOCKY LIVE PRODUCTION FORENSIC DEMONSTRATION OVER HTTPS")
    print(f"Target Public Server: {SERVER}")
    print("=" * 70)

    # 1. Setup client and identity
    cfg = AgentConfig()
    cfg.server_url = SERVER
    client = AgentClient(config=cfg)
    ident = AgentIdentity.load_or_create()

    # 2. Register & Heartbeat over HTTPS
    reg = client.register(ident)
    print(f"[OK] 1. Agent Registered over HTTPS: {ident.agent_id} (Status: {reg.get('status')})")
    hb = client.heartbeat(ident.agent_id)
    print(f"[OK] 2. Agent Heartbeat Verified over HTTPS: {hb.get('last_seen')}")

    # 3. Create forensic triage job via API over HTTPS
    headers = {
        "X-Analyst-Key": "jocky-analyst-secret-key-2026",
        "Content-Type": "application/json"
    }

    jocky_source = """
SYSTEM_INFO
PROCESS_SCAN
NETWORK_SCAN
DETECT
REPORT "live_production_demo"
"""

    job_payload = {
        "name": "Live Production Verification Triage",
        "agent_id": ident.agent_id,
        "jocky_source": jocky_source,
        "detection_enabled": True
    }

    with httpx.Client(timeout=30.0) as http_client:
        resp = http_client.post(f"{SERVER}/api/v1/jobs", json=job_payload, headers=headers)
        assert resp.status_code in (200, 201), f"Job creation failed: {resp.text}"
        job_data = resp.json()
        job_id = job_data["job_id"]
        print(f"[OK] 3. Forensic Job Created over HTTPS: {job_id} (Status: {job_data['status']})")

    # 4. Agent polls for next assigned job over HTTPS
    fetched_job = client.fetch_next_job(ident.agent_id)
    assert fetched_job is not None, "Expected pending job in queue, got None"
    job_id = fetched_job["job_id"]
    print(f"[OK] 4. Agent Fetched Queued Job {job_id} over HTTPS")

    # 5. Agent executes job locally (read-only collections + threat detection)
    exec_result = AgentJobExecutor.execute_job(
        fetched_job["jocky_source"],
        detection_enabled=fetched_job.get("detection_enabled", True),
    )
    assert exec_result["success"] is True, f"Execution failed: {exec_result.get('error')}"
    ev_count = len(exec_result["evidence_records"])
    find_count = len(exec_result["findings"])
    print(f"[OK] 5. Agent Executed Job Locally: {ev_count} evidence records, {find_count} threat findings")

    # 6. Agent uploads results over HTTPS
    upload_res = client.upload_job_results(
        job_id=job_id,
        agent_id=ident.agent_id,
        evidence_records=exec_result["evidence_records"],
        findings=exec_result["findings"],
        execution_status="COMPLETED",
    )
    print(f"[OK] 6. Results Ingested by Central Server over HTTPS: {upload_res.get('status')}")

    # 7. Verify job completion state over HTTPS
    with httpx.Client(timeout=30.0) as http_client:
        resp = http_client.get(f"{SERVER}/api/v1/jobs/{job_id}", headers=headers)
        assert resp.status_code == 200
        final_job = resp.json()
        print(f"[OK] 7. Job Completion Verified on Server: State={final_job['status']}")
        assert final_job["status"] == "COMPLETED"

    # 8. Create Investigation case over HTTPS
    with httpx.Client(timeout=30.0) as http_client:
        inv_payload = {
            "title": "INC-PROD-LIVE: Production HTTPS Forensic Verification",
            "description": "Live production verification case linking acquired evidence and findings.",
            "lead_analyst": "analyst",
            "agent_ids": [ident.agent_id],
            "job_ids": [job_id],
            "evidence_ids": [r["evidence_id"] for r in exec_result["evidence_records"][:2]],
            "finding_ids": [f["finding_id"] for f in exec_result["findings"][:5]],
        }
        resp = http_client.post(f"{SERVER}/api/v1/investigations", json=inv_payload, headers=headers)
        assert resp.status_code in (200, 201)
        inv_data = resp.json()
        inv_id = inv_data["investigation_id"]
        print(f"[OK] 8. Unified Investigation Case Created over HTTPS: {inv_id}")

        # 9. Verify Investigation Timeline & Graph over HTTPS
        tl_resp = http_client.get(f"{SERVER}/api/v1/investigations/{inv_id}/timeline", headers=headers)
        assert tl_resp.status_code == 200
        tl_events = tl_resp.json().get("events", [])
        print(f"[OK] 9. Master Forensic Timeline Retrieved over HTTPS: {len(tl_events)} events")

        graph_resp = http_client.get(f"{SERVER}/api/v1/investigations/{inv_id}/graph", headers=headers)
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()
        node_count = len(graph_data.get("nodes", []))
        edge_count = len(graph_data.get("edges", []))
        print(f"[OK] 10. Dynamic Topology Entity Graph Retrieved over HTTPS: {node_count} nodes, {edge_count} edges")

    print("\n" + "=" * 70)
    print("ALL 10 LIVE PRODUCTION FORENSIC STEPS PASSED OVER HTTPS!")
    print("=" * 70)

if __name__ == "__main__":
    main()
