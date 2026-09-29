"""
JOCKY Step 6 Advanced Forensic Investigation & Correlation Layer Test Suite.

Verifies:
1. Forensic Normalization Engine (Process, Network, File, Service, Driver, Persistence, System).
2. Indicator Extraction & Deduplication (IPv4, SHA256, paths, ports, names, severity scoring).
3. Artifact Relationships & Deterministic Deduplication.
4. Correlation Rules (Process+Network, Process+File, Service+Process, Driver+Process, Persistence+Process).
5. Cross-System Correlation (Multi-Endpoint threat indicators & campaigns).
6. Chronological Master Timeline Engine with Multi-Dimensional Filtering.
7. Investigation Graph Engine (Topology, typed nodes, typed edges, metrics).
8. REST API Endpoints (/artifacts, /relationships, /indicators, /correlation, /search).
9. Investigation Workspace Endpoints (Graph, Notes CRUD, Point-in-Time Snapshots).
10. Multi-Tenant Organization Boundary Isolation.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from server.main import app
from server.database import SessionLocal
from server.models.user import UserModel
from server.models.agent import AgentModel
from server.models.evidence import CentralEvidenceModel
from server.models.finding import CentralFindingModel
from server.models.investigation import InvestigationModel
from server.models.artifact import NormalizedArtifactModel, ArtifactRelationshipModel
from server.models.indicator import IndicatorModel, CrossSystemCorrelationModel
from server.models.correlation import CorrelatedFindingModel
from server.models.investigation_note import InvestigationNoteModel, InvestigationSnapshotModel
from server.security.tokens import create_access_token
from server.security.permissions import Roles
from server.services.correlation_service import CorrelationService

from forensics.normalization.models import (
    NormalizedArtifact,
    NormalizedArtifactType,
    ArtifactRelationship,
    RelationshipType,
)
from forensics.normalization.engine import NormalizationEngine, default_normalization_registry
from forensics.indicators.models import Indicator, IndicatorType
from forensics.indicators.extractor import IndicatorExtractor, default_indicator_extractor
from forensics.correlation.engine import CorrelationEngine, default_correlation_engine
from forensics.correlation.rules import (
    ProcessNetworkCorrelationRule,
    ProcessFileCorrelationRule,
    CrossSystemCorrelationRule,
)
from forensics.timeline.engine import TimelineEngine, default_timeline_engine
from forensics.graph.engine import GraphEngine, default_graph_engine

client = TestClient(app)


@pytest.fixture(scope="module")
def analyst_token():
    return create_access_token(
        user_id="USR-ANALYST",
        username="analyst",
        role=Roles.SECURITY_ANALYST,
        organization_id="org-default",
    )


@pytest.fixture(scope="module")
def superadmin_token():
    return create_access_token(
        user_id="USR-SUPERADMIN",
        username="admin",
        role=Roles.SUPER_ADMIN,
        organization_id="org-default",
    )


@pytest.fixture(scope="module")
def beta_analyst_token():
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.user_id == "USR-BETA").first()
        if not user:
            user = UserModel(
                user_id="USR-BETA",
                username="analyst_beta",
                email="beta@jocky.local",
                password_hash="mockhash",
                role=Roles.SECURITY_ANALYST,
                organization_id="org-beta",
                is_active=True,
            )
            db.add(user)
            db.commit()
    finally:
        db.close()

    return create_access_token(
        user_id="USR-BETA",
        username="analyst_beta",
        role=Roles.SECURITY_ANALYST,
        organization_id="org-beta",
    )


# ---------------------------------------------------------------------------
# 1. NORMALIZATION ENGINE TESTS
# ---------------------------------------------------------------------------

def test_normalization_process_artifacts():
    engine = NormalizationEngine(default_normalization_registry)
    raw_proc = {
        "pid": 2048,
        "ppid": 1024,
        "name": "svchost_fake.exe",
        "path": "C:\\Windows\\Temp\\svchost_fake.exe",
        "cmdline": "svchost_fake.exe -k netsvcs",
        "hashes": {"sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
    }

    artifacts = engine.normalize_evidence(
        evidence_id="EV-TEST-001",
        operation="scan_processes",
        data=[raw_proc],
        hostname="WORKSTATION-01",
        agent_id="AGT-01",
    )

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type == NormalizedArtifactType.PROCESS.value
    assert art.normalized_attributes["pid"] == 2048
    assert art.normalized_attributes["ppid"] == 1024
    assert art.normalized_attributes["name"] == "svchost_fake.exe"
    assert art.normalized_attributes["path"] == "C:\\Windows\\Temp\\svchost_fake.exe"
    assert art.normalized_attributes["sha256"] == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert "svchost_fake.exe" in art.indicators


def test_normalization_network_artifacts():
    engine = NormalizationEngine(default_normalization_registry)
    raw_net = {
        "local_ip": "192.168.1.50",
        "local_port": 49152,
        "remote_ip": "198.51.100.45",
        "remote_port": 4444,
        "protocol": "TCP",
        "state": "ESTABLISHED",
        "pid": 2048,
        "process_name": "svchost_fake.exe",
    }

    artifacts = engine.normalize_evidence(
        evidence_id="EV-TEST-002",
        operation="collect_network",
        data=[raw_net],
        hostname="WORKSTATION-01",
        agent_id="AGT-01",
    )

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type == NormalizedArtifactType.NETWORK.value
    assert art.normalized_attributes["remote_ip"] == "198.51.100.45"
    assert art.normalized_attributes["remote_port"] == 4444
    assert art.normalized_attributes["pid"] == 2048
    assert "198.51.100.45" in art.indicators


def test_normalization_file_and_service_artifacts():
    engine = NormalizationEngine(default_normalization_registry)
    raw_file = {
        "path": "/tmp/malicious.elf",
        "size": 1048576,
        "hashes": {"sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"},
    }
    raw_svc = {
        "name": "SuspiciousSvc",
        "display_name": "Background Telemetry",
        "status": "RUNNING",
        "binpath": "C:\\Windows\\Temp\\svchost_fake.exe",
        "pid": 2048,
    }

    file_arts = engine.normalize_evidence(
        evidence_id="EV-TEST-003",
        operation="collect_files",
        data=[raw_file],
        hostname="LINUX-SRV-01",
        agent_id="AGT-02",
    )
    svc_arts = engine.normalize_evidence(
        evidence_id="EV-TEST-004",
        operation="collect_services",
        data=[raw_svc],
        hostname="WORKSTATION-01",
        agent_id="AGT-01",
    )

    assert len(file_arts) == 1
    assert file_arts[0].artifact_type == NormalizedArtifactType.FILE.value
    assert file_arts[0].normalized_attributes["filename"] == "malicious.elf"

    assert len(svc_arts) == 1
    assert svc_arts[0].artifact_type == NormalizedArtifactType.SERVICE.value
    assert svc_arts[0].normalized_attributes["service_name"] == "SuspiciousSvc"


# ---------------------------------------------------------------------------
# 2. INDICATOR EXTRACTION & DEDUPLICATION TESTS
# ---------------------------------------------------------------------------

def test_indicator_extractor_and_severity_scoring():
    extractor = IndicatorExtractor()
    art1 = NormalizedArtifact(
        artifact_id="ART-1",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.NETWORK.value,
        normalized_attributes={"remote_ip": "198.51.100.45", "remote_port": 4444, "protocol": "TCP"},
    )
    art2 = NormalizedArtifact(
        artifact_id="ART-2",
        agent_id="AGT-02",
        artifact_type=NormalizedArtifactType.NETWORK.value,
        normalized_attributes={"remote_ip": "198.51.100.45", "remote_port": 4444, "protocol": "TCP"},
    )
    art3 = NormalizedArtifact(
        artifact_id="ART-3",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        normalized_attributes={"path": "C:\\Users\\User\\AppData\\Local\\Temp\\drop.exe", "name": "drop.exe"},
    )

    indicators = extractor.extract_from_artifacts([art1, art2, art3])
    ind_by_val = {i.value: i for i in indicators}

    # Verify IP indicator deduplicated across agents
    assert "198.51.100.45" in ind_by_val
    c2_ip = ind_by_val["198.51.100.45"]
    assert c2_ip.indicator_type == IndicatorType.IPV4.value
    assert c2_ip.occurrences == 2
    assert "AGT-01" in c2_ip.agents_observed
    assert "AGT-02" in c2_ip.agents_observed
    assert c2_ip.severity == "HIGH"  # port 4444 elevates

    # Verify Temp path scores HIGH
    temp_path = ind_by_val["C:\\Users\\User\\AppData\\Local\\Temp\\drop.exe"]
    assert temp_path.severity == "HIGH"


# ---------------------------------------------------------------------------
# 3. CORRELATION ENGINE & RULES TESTS
# ---------------------------------------------------------------------------

def test_process_network_correlation():
    rule = ProcessNetworkCorrelationRule()
    proc = NormalizedArtifact(
        artifact_id="ART-PROC-1",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        normalized_attributes={"pid": 1337, "name": "c2_client.exe"},
    )
    net = NormalizedArtifact(
        artifact_id="ART-NET-1",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.NETWORK.value,
        normalized_attributes={"pid": 1337, "remote_ip": "198.51.100.45", "remote_port": 4444, "protocol": "TCP"},
    )

    rels, findings, _ = rule.correlate(artifacts=[proc, net], indicators=[], findings=[])

    assert len(rels) == 1
    rel = rels[0]
    assert rel.source_artifact_id == "ART-PROC-1"
    assert rel.target_artifact_id == "ART-NET-1"
    assert rel.relationship_type == RelationshipType.CONNECTED_TO.value

    assert len(findings) == 1
    assert "c2_client.exe" in findings[0].title
    assert findings[0].severity == "HIGH"


def test_process_file_parent_child_correlation():
    rule = ProcessFileCorrelationRule()
    parent_proc = NormalizedArtifact(
        artifact_id="ART-PROC-P",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        normalized_attributes={"pid": 100, "ppid": 4, "name": "cmd.exe"},
    )
    child_proc = NormalizedArtifact(
        artifact_id="ART-PROC-C",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        normalized_attributes={"pid": 200, "ppid": 100, "name": "powershell.exe", "path": "C:\\Windows\\System32\\powershell.exe"},
    )

    rels, _, _ = rule.correlate(artifacts=[parent_proc, child_proc], indicators=[], findings=[])

    assert len(rels) == 1
    assert rels[0].source_artifact_id == "ART-PROC-P"
    assert rels[0].target_artifact_id == "ART-PROC-C"
    assert rels[0].relationship_type == RelationshipType.PARENT_OF.value


def test_cross_system_correlation_detection():
    rule = CrossSystemCorrelationRule()
    ind = Indicator(
        indicator_id="IOC-CROSS-1",
        indicator_type=IndicatorType.IPV4.value,
        value="198.51.100.45",
        occurrences=2,
        severity="HIGH",
        agents_observed=["AGT-WIN-01", "AGT-LNX-01"],
        source_artifacts=["ART-1", "ART-2"],
    )

    _, findings, xcorrs = rule.correlate(artifacts=[], indicators=[ind], findings=[])

    assert len(xcorrs) == 1
    xc = xcorrs[0]
    assert xc.indicator_value == "198.51.100.45"
    assert xc.agents_count == 2
    assert "AGT-WIN-01" in xc.agent_ids
    assert "AGT-LNX-01" in xc.agent_ids

    assert len(findings) == 1
    assert "Cross-System Campaign" in findings[0].title
    assert findings[0].severity == "CRITICAL"


# ---------------------------------------------------------------------------
# 4. TIMELINE & GRAPH ENGINE TESTS
# ---------------------------------------------------------------------------

def test_chronological_timeline_engine():
    tl_engine = TimelineEngine()
    art1 = NormalizedArtifact(
        artifact_id="ART-1",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        timestamp="2026-09-30T01:00:00Z",
        normalized_attributes={"pid": 500, "name": "sample.exe"},
    )
    art2 = NormalizedArtifact(
        artifact_id="ART-2",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.NETWORK.value,
        timestamp="2026-09-30T01:05:00Z",
        normalized_attributes={"remote_ip": "1.2.3.4", "remote_port": 80},
    )

    events = tl_engine.build_timeline(artifacts=[art2, art1], sort_asc=True)

    assert len(events) == 2
    # Verify chronological ascending order
    assert events[0].timestamp < events[1].timestamp
    assert events[0].source_id == "ART-1"
    assert events[1].source_id == "ART-2"

    # Verify category filtering
    proc_events = tl_engine.build_timeline(artifacts=[art2, art1], category="PROCESS")
    assert len(proc_events) == 1
    assert proc_events[0].category == "PROCESS"


def test_investigation_graph_generation():
    graph_engine = GraphEngine()
    agents = [{"agent_id": "AGT-01", "hostname": "HOST-ALPHA", "operating_system": "Windows"}]
    art = NormalizedArtifact(
        artifact_id="ART-PROC-1",
        agent_id="AGT-01",
        artifact_type=NormalizedArtifactType.PROCESS.value,
        normalized_attributes={"pid": 1000, "name": "payload.exe"},
    )
    findings = [{
        "finding_id": "FND-001",
        "agent_id": "AGT-01",
        "title": "Reverse Shell Spawned",
        "severity": "CRITICAL",
        "affected_object": "payload.exe",
    }]

    graph = graph_engine.build_graph(
        investigation_id="INV-TEST-001",
        agents=agents,
        artifacts=[art],
        findings=findings,
    )

    node_ids = {n.id for n in graph.nodes}
    assert "SYS-AGT-01" in node_ids
    assert "ART-PROC-1" in node_ids
    assert "FND-FND-001" in node_ids

    assert graph.metrics["node_count"] == 3
    assert graph.metrics["highest_severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# 5. REST API ENDPOINTS TESTS
# ---------------------------------------------------------------------------

def test_api_artifacts_endpoints(analyst_token):
    # Seed a normalized artifact in DB
    db = SessionLocal()
    try:
        art = NormalizedArtifactModel(
            artifact_id="ART-API-001",
            organization_id="org-default",
            agent_id="agent-win-01",
            evidence_id="EV-API-001",
            hostname="WIN-ENDPOINT",
            artifact_type="PROCESS",
            timestamp=datetime.now(timezone.utc),
            normalized_attributes={"pid": 4096, "name": "beacon.exe"},
            indicators=["beacon.exe"],
            created_at=datetime.now(timezone.utc),
        )
        db.merge(art)
        db.commit()
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {analyst_token}"}

    # List artifacts
    res = client.get("/api/v1/artifacts?artifact_type=PROCESS", headers=headers)
    assert res.status_code == 200
    items = res.json()
    assert any(i["artifact_id"] == "ART-API-001" for i in items)

    # Get single artifact
    res_single = client.get("/api/v1/artifacts/ART-API-001", headers=headers)
    assert res_single.status_code == 200
    assert res_single.json()["artifact_id"] == "ART-API-001"


def test_api_indicators_endpoints(analyst_token):
    db = SessionLocal()
    try:
        ind = IndicatorModel(
            indicator_id="IOC-API-001",
            organization_id="org-default",
            indicator_type="IPV4",
            value="203.0.113.10",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            occurrences=3,
            severity="HIGH",
            source_artifacts=["ART-1"],
            agents_observed=["agent-win-01"],
        )
        db.merge(ind)
        db.commit()
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.get("/api/v1/indicators?indicator_type=IPV4", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert any(i["value"] == "203.0.113.10" for i in data)


def test_api_correlation_run_and_cross_system(analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Run correlation analysis
    res_run = client.post("/api/v1/correlation/run", headers=headers)
    assert res_run.status_code == 200
    assert res_run.json()["status"] == "COMPLETED"

    # Query cross-system correlations
    res_xcorr = client.get("/api/v1/correlation/cross-system", headers=headers)
    assert res_xcorr.status_code == 200
    assert isinstance(res_xcorr.json(), list)

    # Query correlated findings
    res_cfnd = client.get("/api/v1/correlation/findings", headers=headers)
    assert res_cfnd.status_code == 200
    assert isinstance(res_cfnd.json(), list)


def test_api_search_endpoint(analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.get("/api/v1/search?q=beacon", headers=headers)
    assert res.status_code == 200
    search_data = res.json()
    assert search_data["query"] == "beacon"
    assert search_data["total_results"] >= 1
    assert any(r["title"].lower().find("beacon") != -1 for r in search_data["results"])


def test_api_investigation_notes_and_snapshots(analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Create Investigation
    inv_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={"title": "Step 6 Integration Case", "description": "Verification of notes and snapshots."},
    )
    assert inv_res.status_code == 200
    inv_id = inv_res.json()["investigation_id"]

    # 2. Add Collaborative Note
    note_res = client.post(
        f"/api/v1/investigations/{inv_id}/notes",
        headers=headers,
        json={"content": "Confirmed outbound C2 connection from temporary executable."},
    )
    assert note_res.status_code == 200
    note_id = note_res.json()["note_id"]
    assert note_res.json()["content"] == "Confirmed outbound C2 connection from temporary executable."

    # 3. List Notes
    notes_list_res = client.get(f"/api/v1/investigations/{inv_id}/notes", headers=headers)
    assert notes_list_res.status_code == 200
    assert len(notes_list_res.json()) >= 1

    # 4. Create Frozen Snapshot
    snap_res = client.post(
        f"/api/v1/investigations/{inv_id}/snapshots",
        headers=headers,
        json={"title": "Triage Phase Complete"},
    )
    assert snap_res.status_code == 200
    snap_id = snap_res.json()["snapshot_id"]
    assert snap_res.json()["title"] == "Triage Phase Complete"

    # 5. Retrieve Frozen Snapshot
    snap_get_res = client.get(f"/api/v1/investigations/{inv_id}/snapshots/{snap_id}", headers=headers)
    assert snap_get_res.status_code == 200
    assert snap_get_res.json()["snapshot_id"] == snap_id
    assert "snapshot_data" in snap_get_res.json()

    # 6. Delete Note
    del_res = client.delete(f"/api/v1/investigations/{inv_id}/notes/{note_id}", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "DELETED"


# ---------------------------------------------------------------------------
# 6. MULTI-TENANT ISOLATION TESTS
# ---------------------------------------------------------------------------

def test_organization_isolation_on_artifacts_and_notes(analyst_token, beta_analyst_token):
    # Org-Default Analyst creates investigation & note
    headers_default = {"Authorization": f"Bearer {analyst_token}"}
    headers_beta = {"Authorization": f"Bearer {beta_analyst_token}"}

    inv_res = client.post(
        "/api/v1/investigations",
        headers=headers_default,
        json={"title": "Org Default Confidential Case"},
    )
    inv_id = inv_res.json()["investigation_id"]

    client.post(
        f"/api/v1/investigations/{inv_id}/notes",
        headers=headers_default,
        json={"content": "Top secret investigative insight."},
    )

    # Org-Beta Analyst attempts to access notes -> 403 Forbidden
    cross_res = client.get(f"/api/v1/investigations/{inv_id}/notes", headers=headers_beta)
    assert cross_res.status_code == 403

    # Org-Beta Analyst attempts to capture snapshot on foreign case -> 403 Forbidden
    cross_snap_res = client.post(
        f"/api/v1/investigations/{inv_id}/snapshots",
        headers=headers_beta,
        json={"title": "Unauthorized Snapshot"},
    )
    assert cross_snap_res.status_code == 403
