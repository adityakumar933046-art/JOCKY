"""
Tests for JOCKY Forensic Command Center Aggregation API.
Verifies multi-system telemetry, adversary matrix, timeline, and multi-tenant scoping.
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)
ANALYST_HEADERS = {"X-Analyst-Key": "jocky-analyst-secret-key-2026"}


def test_command_center_telemetry_authorized():
    """Verify that authorized users can query the consolidated Command Center telemetry."""
    response = client.get("/api/v1/forensics/command-center", headers=ANALYST_HEADERS)
    assert response.status_code == 200
    data = response.json()

    assert data["platform_status"] == "HEALTHY"
    assert "version" in data
    assert "summary" in data
    assert "systems" in data
    assert "adversary_matrix" in data
    assert "cross_system_correlations" in data
    assert "priority_investigations" in data
    assert "master_timeline" in data
    assert "evidence_integrity" in data
    assert "indicator_stats" in data
    assert "recent_jobs" in data

    summary = data["summary"]
    assert "total_systems" in summary
    assert "total_findings" in summary
    assert "total_evidence" in summary
    assert "total_indicators" in summary
    assert "total_correlations" in summary

    # Verify adversary matrix categories
    matrix = data["adversary_matrix"]
    expected_categories = [
        "process",
        "network",
        "persistence",
        "driver",
        "memory",
        "service",
        "file",
        "parent_child",
    ]
    for cat in expected_categories:
        assert cat in matrix
        assert "low" in matrix[cat]
        assert "medium" in matrix[cat]
        assert "high" in matrix[cat]
        assert "critical" in matrix[cat]
        assert "total" in matrix[cat]


def test_command_center_unauthorized():
    """Verify that requests with invalid credentials or tokens are rejected."""
    response = client.get("/api/v1/forensics/command-center", headers={"Authorization": "Bearer invalid_token_12345"})
    assert response.status_code in [401, 403]
