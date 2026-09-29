"""
Unit tests for JOCKY Server Agent Management API.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.config import config

client = TestClient(app)
AUTH_HEADERS = {"X-Agent-Key": config.AGENT_SECRET_KEY}


def test_agent_registration():
    payload = {
        "agent_id": "AGT-TEST01",
        "hostname": "TEST-HOST-01",
        "operating_system": "Windows",
        "os_version": "10.0.19045",
        "architecture": "x86_64",
        "jocky_version": "1.0.0",
        "collector_version": "1.0.0",
    }
    resp = client.post("/api/v1/agents/register", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["registered"] is True
    assert data["agent_id"] == "AGT-TEST01"
    assert data["status"] == "ONLINE"


def test_agent_heartbeat():
    resp = client.post("/api/v1/agents/AGT-TEST01/heartbeat", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "AGT-TEST01"
    assert data["status"] == "ONLINE"


def test_agent_listing():
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    agents = resp.json()
    assert len(agents) >= 1
    found = [a for a in agents if a["agent_id"] == "AGT-TEST01"]
    assert len(found) == 1
    assert found[0]["hostname"] == "TEST-HOST-01"


def test_agent_get_by_id():
    resp = client.get("/api/v1/agents/AGT-TEST01")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "AGT-TEST01"
    assert data["operating_system"] == "Windows"


def test_agent_get_nonexistent():
    resp = client.get("/api/v1/agents/NONEXISTENT-AGENT")
    assert resp.status_code == 404
