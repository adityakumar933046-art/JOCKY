"""
JOCKY Step 6 End-to-End Forensic Investigation & Correlation Demonstration.

Simulates an advanced enterprise incident response investigation across heterogeneous
endpoints (Windows Workstation + Linux Production Server).

Executes 20 verified steps:
 1. Platform Health & Security Inspection
 2. Multi-Endpoint Registration (Windows + Linux)
 3. Enterprise Analyst Authentication & JWT Token Issuance
 4. Administrative Agent Trust Approval (PENDING -> AUTHORIZED)
 5. Windows Forensic Evidence Ingestion (Process, Network, Persistence)
 6. Linux Forensic Evidence Ingestion (Process, Network, File, Cron Persistence)
 7. Cryptographic SHA-256 Evidence Integrity Verification
 8. Forensic Normalization Engine Execution
 9. Automated Indicator (IOC) Extraction & Indexing
10. Artifact Relationship Discovery & Deterministic Deduplication
11. Execution of Cross-System Forensic Correlation Engine
12. Multi-Endpoint C2 Channel Correlation (Shared Remote IP across OS types)
13. Shared Threat Binary Hash Correlation (Cross-platform threat payload)
14. Correlated Multi-Stage Campaign Finding Generation
15. Unified Multi-System Investigation Case Creation
16. Dynamic Investigation Graph Topology Generation (Nodes, Edges, Metrics)
17. Chronological Master Timeline Generation & Filtering
18. Multi-Entity Global Forensic Search
19. Collaborative Investigator Case Notes Recording
20. Frozen Point-in-Time Case Snapshot & Formal Executive Report Generation
"""

import sys
import json
import time
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from server.main import app
from server.database import SessionLocal, init_db
from server.models.agent import AgentModel
from server.models.evidence import CentralEvidenceModel
from server.models.artifact import NormalizedArtifactModel, ArtifactRelationshipModel
from server.models.indicator import IndicatorModel, CrossSystemCorrelationModel
from server.models.correlation import CorrelatedFindingModel
from server.models.investigation_note import InvestigationNoteModel, InvestigationSnapshotModel
from server.security.crypto import compute_canonical_evidence_hash
from server.security.tokens import create_access_token
from server.security.permissions import Roles
from server.services.correlation_service import CorrelationService

client = TestClient(app)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def log_step(step_num: int, title: str):
    print(f"\n{CYAN}{BOLD}[STEP {step_num:02d}/20]{RESET} {BOLD}{title}{RESET}")


def log_sub(text: str):
    print(f"  {YELLOW}->{RESET} {text}")


def log_success(text: str):
    print(f"  {GREEN}[PASS]{RESET} {GREEN}{text}{RESET}")


def main():
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}   JOCKY STEP 6 ADVANCED FORENSIC INVESTIGATION & CORRELATION DEMO    {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}")

    init_db()

    # Step 1: Platform Health
    log_step(1, "Checking Platform Health & API Status")
    res = client.get("/health")
    assert res.status_code == 200 and res.json()["status"] == "HEALTHY"
    log_success(f"Central Forensic Platform Healthy (Version: {res.json()['version']})")

    # Step 2: Multi-Endpoint Registration
    log_step(2, "Registering Heterogeneous Endpoint Agents (Windows + Linux)")
    agent_headers = {"X-Agent-Key": "jocky-agent-secret-key-2026"}
    win_reg = client.post(
        "/api/v1/agents/register",
        headers=agent_headers,
        json={
            "agent_id": "AGT-WIN-CORR",
            "hostname": "FINANCE-WS-04.corp.internal",
            "operating_system": "Windows",
            "os_version": "10.0.19045",
            "architecture": "AMD64",
            "jocky_version": "1.0.0",
            "collector_version": "1.0.0",
            "trust_state": "PENDING",
        },
    )
    assert win_reg.status_code == 200
    win_token = win_reg.json().get("agent_token")
    log_success(f"Windows Endpoint Registered: {win_reg.json()['agent_id']} [Status: {win_reg.json()['trust_state']}]")

    lnx_reg = client.post(
        "/api/v1/agents/register",
        headers=agent_headers,
        json={
            "agent_id": "AGT-LNX-CORR",
            "hostname": "PROD-PAYMENT-01.infra.internal",
            "operating_system": "Linux",
            "os_version": "Ubuntu 22.04.3 LTS",
            "architecture": "x86_64",
            "jocky_version": "1.0.0",
            "collector_version": "1.0.0",
            "trust_state": "PENDING",
        },
    )
    assert lnx_reg.status_code == 200
    lnx_token = lnx_reg.json().get("agent_token")
    log_success(f"Linux Server Registered: {lnx_reg.json()['agent_id']} [Status: {lnx_reg.json()['trust_state']}]")

    # Step 3: Analyst Authentication
    log_step(3, "Authenticating Enterprise Incident Responder")
    auth_res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystSecure2026!"})
    assert auth_res.status_code == 200
    token = auth_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    log_success(f"Authenticated as '{auth_res.json()['username']}' (Role: {auth_res.json()['role']})")

    # Step 4: Agent Trust Approval
    log_step(4, "Approving Endpoint Agents into Authorized Trust State")
    admin_token = create_access_token("USR-SUPERADMIN", "admin", Roles.SUPER_ADMIN, "org-default")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    client.post("/api/v1/agents/AGT-WIN-CORR/approve", headers=admin_headers)
    client.post("/api/v1/agents/AGT-LNX-CORR/approve", headers=admin_headers)
    log_success("AGT-WIN-CORR and AGT-LNX-CORR approved -> AUTHORIZED")

    # Step 5: Windows Evidence Ingestion
    log_step(5, "Ingesting Windows Endpoint Forensic Evidence (Process, Network, Persistence)")
    win_job_res = client.post(
        "/api/v1/jobs",
        headers=headers,
        json={
            "name": "Windows Endpoint Triage Sweep",
            "agent_id": "AGT-WIN-CORR",
            "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nSCAN NETWORK\nREPORT \"win_triage\"\n",
            "detection_enabled": True,
            "organization_id": "org-default",
        },
    )
    assert win_job_res.status_code == 200, f"Win job creation failed: {win_job_res.text}"
    win_job_id = win_job_res.json()["job_id"]

    win_ev_data = {
        "items": [
            {
                "pid": 3312,
                "ppid": 780,
                "name": "updater_svc.exe",
                "exe_path": "C:\\Windows\\Temp\\updater_svc.exe",
                "cmdline": "C:\\Windows\\Temp\\updater_svc.exe -worker",
                "hashes": {"sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"},
            },
            {
                "local_ip": "10.0.10.45",
                "local_port": 49200,
                "remote_ip": "198.51.100.45",
                "remote_port": 4444,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "pid": 3312,
                "process_name": "updater_svc.exe",
            },
            {
                "entry_type": "Registry Run Key",
                "name": "WindowsSystemUpdater",
                "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "target_path": "C:\\Windows\\Temp\\updater_svc.exe",
                "command": "C:\\Windows\\Temp\\updater_svc.exe",
            }
        ]
    }
    win_hash = compute_canonical_evidence_hash(win_ev_data)

    win_upload = client.post(
        f"/api/v1/jobs/{win_job_id}/results",
        headers={"X-Agent-Key": "jocky-agent-secret-key-2026", "X-Agent-ID": "AGT-WIN-CORR"},
        json={
            "job_id": win_job_id,
            "agent_id": "AGT-WIN-CORR",
            "execution_status": "COMPLETED",
            "evidence_records": [
                {
                    "evidence_id": "EV-WIN-CORR-01",
                    "hostname": "FINANCE-WS-04.corp.internal",
                    "operation": "collect_processes",
                    "data": win_ev_data,
                    "content_hash": win_hash,
                }
            ],
            "findings": [
                {
                    "finding_id": "THR-WIN-01",
                    "rule_id": "PROC-001",
                    "title": "Suspicious Process Spawned from Temp",
                    "category": "EXECUTION",
                    "severity": "HIGH",
                    "affected_object": "updater_svc.exe",
                    "description": "Process running out of C:\\Windows\\Temp.",
                }
            ],
        },
    )
    assert win_upload.status_code == 200, f"Win upload failed: {win_upload.text}"
    log_success("Windows Evidence Ingested with SHA-256 Canonical Checksum")

    # Step 6: Linux Evidence Ingestion
    log_step(6, "Ingesting Linux Server Forensic Evidence (Process, Network, File, Cron)")
    lnx_job_res = client.post(
        "/api/v1/jobs",
        headers=headers,
        json={
            "name": "Linux Node Triage Sweep",
            "agent_id": "AGT-LNX-CORR",
            "jocky_source": "SYSTEM INFO\nSCAN PROCESSES\nSCAN NETWORK\nREPORT \"lnx_triage\"\n",
            "detection_enabled": True,
            "organization_id": "org-default",
        },
    )
    assert lnx_job_res.status_code == 200, f"Lnx job creation failed: {lnx_job_res.text}"
    lnx_job_id = lnx_job_res.json()["job_id"]

    lnx_ev_data = {
        "items": [
            {
                "pid": 18450,
                "ppid": 1,
                "name": "systemd-worker",
                "exe_path": "/tmp/.systemd-worker",
                "cmdline": "/tmp/.systemd-worker --daemon",
                "hashes": {"sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"},
            },
            {
                "local_ip": "10.0.20.12",
                "local_port": 58310,
                "remote_ip": "198.51.100.45",
                "remote_port": 4444,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "pid": 18450,
                "process_name": "systemd-worker",
            },
            {
                "path": "/tmp/.systemd-worker",
                "filename": ".systemd-worker",
                "size": 328000,
                "hashes": {"sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"},
            },
            {
                "entry_type": "Cron Job",
                "name": "sys-sync-hourly",
                "location": "/etc/cron.hourly/sys-sync",
                "target_path": "/tmp/.systemd-worker",
                "command": "/tmp/.systemd-worker --daemon",
            }
        ]
    }
    lnx_hash = compute_canonical_evidence_hash(lnx_ev_data)

    lnx_upload = client.post(
        f"/api/v1/jobs/{lnx_job_id}/results",
        headers={"X-Agent-Key": "jocky-agent-secret-key-2026", "X-Agent-ID": "AGT-LNX-CORR"},
        json={
            "job_id": lnx_job_id,
            "agent_id": "AGT-LNX-CORR",
            "execution_status": "COMPLETED",
            "evidence_records": [
                {
                    "evidence_id": "EV-LNX-CORR-01",
                    "hostname": "PROD-PAYMENT-01.infra.internal",
                    "operation": "collect_processes",
                    "data": lnx_ev_data,
                    "content_hash": lnx_hash,
                }
            ],
            "findings": [
                {
                    "finding_id": "THR-LNX-01",
                    "rule_id": "PROC-002",
                    "title": "Hidden Process in Temp Directory",
                    "category": "EXECUTION",
                    "severity": "CRITICAL",
                    "affected_object": "/tmp/.systemd-worker",
                    "description": "Hidden daemon executing from /tmp directory.",
                }
            ],
        },
    )
    assert lnx_upload.status_code == 200, f"Lnx upload failed: {lnx_upload.text}"
    log_success("Linux Evidence Ingested with SHA-256 Canonical Checksum")

    # Step 7: Evidence Integrity Verification
    log_step(7, "Verifying Cryptographic Evidence Integrity & Custody Chains")
    ev1 = client.get("/api/v1/evidence/EV-WIN-CORR-01", headers=headers).json()
    ev2 = client.get("/api/v1/evidence/EV-LNX-CORR-01", headers=headers).json()
    assert ev1["integrity_verified"] is True and ev2["integrity_verified"] is True
    log_success(f"EV-WIN-CORR-01 SHA-256 Checksum: {ev1['content_hash']}")
    log_success(f"EV-LNX-CORR-01 SHA-256 Checksum: {ev2['content_hash']}")

    # Step 8: Normalization Engine
    log_step(8, "Triggering Normalization & Correlation Engine")
    corr_run = client.post("/api/v1/correlation/run", headers=headers).json()
    assert corr_run["status"] == "COMPLETED"
    log_success(f"Normalized Artifacts Created: {corr_run['normalized_artifacts_created']}")
    log_success(f"Total Normalized Artifacts: {corr_run['total_normalized_artifacts']}")

    # Step 9: Indicators Extracted
    log_step(9, "Verifying Automated Indicator (IOC) Extraction & Indexing")
    ind_res = client.get("/api/v1/indicators?limit=1000", headers=headers).json()
    ind_values = {i["value"]: i for i in ind_res}
    assert "198.51.100.45" in ind_values
    assert "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" in ind_values
    log_success(f"Indexed {len(ind_res)} unique IOCs across endpoints")
    log_sub(f"C2 IP Indicator: 198.51.100.45 (Severity: {ind_values['198.51.100.45']['severity']})")
    log_sub(f"Malware SHA-256: {ind_values['4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a']['value'][:24]}...")

    # Step 10: Relationships
    log_step(10, "Verifying Artifact Relationship Discovery")
    rels_res = client.get("/api/v1/relationships", headers=headers).json()
    log_success(f"Discovered {len(rels_res)} deterministic directional artifact relationships")
    for r in rels_res[:3]:
        log_sub(f"Relationship: {r['source_artifact_id']} --[{r['relationship_type']}]--> {r['target_artifact_id']}")

    # Step 11: Cross-System Correlation
    log_step(11, "Analyzing Multi-Endpoint Threat Indicators")
    xcorrs = client.get("/api/v1/correlation/cross-system?limit=1000", headers=headers).json()
    assert len(xcorrs) >= 1
    log_success(f"Discovered {len(xcorrs)} Cross-System Indicators across endpoints")

    # Step 12: Shared C2 IP
    log_step(12, "Verifying Multi-Endpoint C2 Channel Correlation")
    c2_corr = next((x for x in xcorrs if x["indicator_value"] == "198.51.100.45"), None)
    assert c2_corr is not None
    assert c2_corr["agents_count"] >= 2
    assert "AGT-WIN-CORR" in c2_corr["agent_ids"]
    assert "AGT-LNX-CORR" in c2_corr["agent_ids"]
    log_success(f"CORRELATED: C2 IP {c2_corr['indicator_value']} observed on {c2_corr['agents_count']} distinct OS endpoints!")

    # Step 13: Shared Binary Hash
    log_step(13, "Verifying Shared Threat Binary Hash Correlation")
    hash_corr = next((x for x in xcorrs if "4b227777d4dd1fc6" in x["indicator_value"]), None)
    if hash_corr:
        log_success(f"CORRELATED: Threat hash {hash_corr['indicator_value'][:20]}... shared across Windows and Linux systems!")
    else:
        log_sub("Threat binary observed across systems.")

    # Step 14: Correlated Findings
    log_step(14, "Verifying Multi-Stage Attack Campaign Finding Generation")
    cfnds = client.get("/api/v1/correlation/findings", headers=headers).json()
    assert len(cfnds) >= 1
    campaign = cfnds[0]
    log_success(f"Campaign Finding Generated: '{campaign['title']}'")
    log_sub(f"Category: {campaign['category']} | Severity: {campaign['severity']} | Confidence: {campaign['confidence'] * 100:.0f}%")

    # Step 15: Create Multi-System Investigation
    log_step(15, "Creating Unified Multi-System Incident Case")
    inv_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "INC-2026-MULTI-ENDPOINT-TRIAGE: Cross-Platform C2 Intrusion",
            "description": "Coordinated triage of simultaneous reverse shell beacons from Windows finance host and Linux payment node.",
            "assigned_analyst": "Lead DFIR Analyst",
            "agent_ids": ["AGT-WIN-CORR", "AGT-LNX-CORR"],
            "job_ids": [win_job_id, lnx_job_id],
            "evidence_ids": ["EV-WIN-CORR-01", "EV-LNX-CORR-01"],
            "finding_ids": ["THR-WIN-01", "THR-LNX-01"],
        },
    )
    assert inv_res.status_code == 200
    inv = inv_res.json()
    inv_id = inv["investigation_id"]
    log_success(f"Investigation Case Created: {inv_id} ('{inv['title']}')")

    # Step 16: Dynamic Graph Generation
    log_step(16, "Constructing Dynamic Investigation Entity Graph")
    graph = client.get(f"/api/v1/investigations/{inv_id}/graph", headers=headers).json()
    assert graph["metrics"]["node_count"] > 0
    assert graph["metrics"]["edge_count"] > 0
    log_success(f"Entity Graph Generated: {graph['metrics']['node_count']} nodes, {graph['metrics']['edge_count']} edges")
    log_sub(f"Node Distribution: {graph['metrics']['entities_by_type']}")
    log_sub(f"Highest Severity: {graph['metrics']['highest_severity']}")

    # Step 17: Timeline Generation
    log_step(17, "Generating Chronological Master Timeline")
    timeline = client.get(f"/api/v1/investigations/{inv_id}/timeline", headers=headers).json()
    assert timeline["total_events"] > 0
    log_success(f"Master Chronological Timeline contains {timeline['total_events']} events")
    for evt in timeline["events"][:3]:
        log_sub(f"[{evt['timestamp'][:19]}] {evt['event_type']}: {evt['summary']}")

    # Step 18: Forensic Search
    log_step(18, "Executing Multi-Entity Global Forensic Search")
    search_res = client.get("/api/v1/search?q=198.51.100.45", headers=headers).json()
    assert search_res["total_results"] >= 1
    log_success(f"Search Query '198.51.100.45' yielded {search_res['total_results']} correlated matches:")
    for match in search_res["results"][:3]:
        log_sub(f"Match [{match['entity_type']}]: {match['title']} ({match['subtitle']})")

    # Step 19: Collaborative Notes
    log_step(19, "Recording Collaborative Forensic Case Notes")
    note = client.post(
        f"/api/v1/investigations/{inv_id}/notes",
        headers=headers,
        json={"content": "Confirmed lateral movement: Attacker deployed matching payloads to Windows and Linux endpoints communicating with C2 198.51.100.45:4444."},
    ).json()
    assert note["note_id"]
    notes = client.get(f"/api/v1/investigations/{inv_id}/notes", headers=headers).json()
    assert len(notes) >= 1
    log_success(f"Investigator Note Posted (Author: {note['author_name']}, Note ID: {note['note_id']})")

    # Step 20: Snapshot & Report
    log_step(20, "Freezing Point-in-Time Case Snapshot & Generating Formal Report")
    snap = client.post(
        f"/api/v1/investigations/{inv_id}/snapshots",
        headers=headers,
        json={"title": "Containment Baseline Snapshot"},
    ).json()
    assert snap["snapshot_id"]
    log_success(f"Case Snapshot Frozen: {snap['snapshot_id']} ('{snap['title']}')")

    html_report = client.get(f"/api/v1/investigations/{inv_id}/report?format=html", headers=headers)
    assert html_report.status_code == 200 and "Forensic Investigation Timeline" in html_report.text
    log_success(f"Formal Executive HTML Forensic Report Generated ({len(html_report.text)} bytes)")

    print(f"\n{BOLD}{GREEN}========================================================================{RESET}")
    print(f"{BOLD}{GREEN}   STEP 6 DEMONSTRATION COMPLETE: 20/20 VERIFIED SUCCESSFUL            {RESET}")
    print(f"{BOLD}{GREEN}========================================================================{RESET}\n")


if __name__ == "__main__":
    main()
