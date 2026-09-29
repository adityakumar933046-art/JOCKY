"""
Unit tests for JOCKY API Security, Role Separation, and Compiler Validation.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": config.ANALYST_SECRET_KEY}
AGENT_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}
WRONG_HEADERS = {"X-Agent-Key": "wrong-secret-key-1234"}


def test_agent_endpoint_rejects_invalid_key():
    resp = client.post(
        "/api/v1/agents/register",
        json={"agent_id": "AGT-SEC", "hostname": "SEC-HOST", "operating_system": "Windows"},
        headers=WRONG_HEADERS,
    )
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]


def test_analyst_endpoint_rejects_invalid_key():
    resp = client.post(
        "/api/v1/investigations",
        json={"title": "Unauthorized Investigation"},
        headers={"X-Analyst-Key": "invalid-analyst-key"},
    )
    assert resp.status_code == 401


def test_compiler_validate_valid_script():
    payload = {
        "source": "SYSTEM INFO\nSCAN PROCESSES\nSCAN NETWORK\nREPORT \"valid_report\""
    }
    resp = client.post("/api/v1/compiler/validate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert len(data["errors"]) == 0
    assert data["instructions_count"] == 4


def test_compiler_validate_invalid_syntax():
    payload = {
        "source": "SCAN @INVALID_CHARACTER\n"
    }
    resp = client.post("/api/v1/compiler/validate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["errors"]) > 0
    assert len(data["diagnostics"]) > 0


def test_compiler_validate_ir_allowlist_rejection():
    # If script compiles but attempts unapproved target or structure
    payload = {
        "source": "REPORT \"only_report_without_collection\""
    }
    resp = client.post("/api/v1/compiler/validate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert any("before any forensic collection" in e for e in data["errors"])
