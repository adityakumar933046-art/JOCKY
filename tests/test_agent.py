"""
Unit tests for JOCKY Agent Identity, Executor, and Client.
"""

import json
from pathlib import Path
from agent.identity import AgentIdentity
from agent.executor import AgentJobExecutor


def test_agent_identity_persistence(tmp_path):
    id_file = tmp_path / "agent_id.json"
    ident1 = AgentIdentity.load_or_create(storage_path=str(id_file))
    assert ident1.agent_id.startswith("AGT-")
    assert ident1.hostname is not None

    # Reload from file and ensure it retains identical ID
    ident2 = AgentIdentity.load_or_create(storage_path=str(id_file))
    assert ident1.agent_id == ident2.agent_id


def test_agent_executor_valid_job():
    script = """
    SYSTEM INFO
    SCAN FILES
    REPORT "agent_test_report"
    """
    res = AgentJobExecutor.execute_job(script, detection_enabled=True)
    assert res["success"] is True
    assert len(res["evidence_records"]) >= 2
    assert res["error"] is None


def test_agent_executor_invalid_jocky():
    script = "INVALID_COMMAND_HERE"
    res = AgentJobExecutor.execute_job(script)
    assert res["success"] is False
    assert "Agent compilation validation failed" in res["error"]


def test_agent_executor_ir_allowlist_violation():
    # Attempting to bypass with an unapproved target or arbitrary structure
    script = "SCAN UNAPPROVED_TARGET"
    res = AgentJobExecutor.execute_job(script)
    assert res["success"] is False
    assert "Agent compilation validation failed" in res["error"] or "Agent Security Rejection" in res["error"]
