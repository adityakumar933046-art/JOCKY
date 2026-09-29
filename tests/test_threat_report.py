"""
Unit tests for the JOCKY Threat Report Generator.
"""

import json
from pathlib import Path
from detection.models import DetectionResult, Finding
from detection.severity import Severity
from reports.threat_report import ThreatReport


def test_threat_report_json_generation(tmp_path):
    f1 = Finding(
        finding_id="THR-000001",
        rule_id="PROC-001",
        title="Suspicious Process Relationship",
        category="PROCESS",
        severity=Severity.HIGH,
        confidence=0.91,
        description="PowerShell spawned unknown child.",
        hostname="DESKTOP-ABC",
        evidence_ids=["EV-000023"],
        affected_object="example.exe",
        indicators={"parent": "powershell.exe", "child": "example.exe"},
        recommendation="Review process ancestry.",
    )

    result = DetectionResult(
        hostname="DESKTOP-ABC",
        findings=[f1],
        summary={"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0},
    )

    report = ThreatReport(result)
    json_str = report.to_json()
    data = json.loads(json_str)

    assert data["hostname"] == "DESKTOP-ABC"
    assert data["total_findings"] == 1
    assert data["summary"]["HIGH"] == 1
    assert data["findings"][0]["finding_id"] == "THR-000001"
    assert data["findings"][0]["severity"] == "HIGH"

    # Test file saving
    save_path = tmp_path / "custom_threat_report.json"
    saved = report.save(save_path)
    assert saved.exists()
    assert json.loads(saved.read_text(encoding="utf-8"))["total_findings"] == 1


def test_threat_report_console_formatting():
    f1 = Finding(
        finding_id="THR-000001",
        rule_id="PROC-001",
        title="Suspicious Process Relationship",
        severity=Severity.HIGH,
        hostname="DESKTOP-ABC",
        evidence_ids=["EV-000023"],
    )
    f2 = Finding(
        finding_id="THR-000002",
        rule_id="PERSIST-001",
        title="Potentially Suspicious Persistence Entry",
        severity=Severity.MEDIUM,
        hostname="DESKTOP-ABC",
        evidence_ids=["EV-000027"],
    )

    result = DetectionResult(
        hostname="DESKTOP-ABC",
        findings=[f1, f2],
        summary={"INFO": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0},
    )

    report = ThreatReport(result)
    console_out = report.format_console()

    assert "[JOCKY THREAT ANALYSIS]" in console_out
    assert "Host: DESKTOP-ABC" in console_out
    assert "[HIGH]" in console_out
    assert "THR-000001" in console_out
    assert "EV-000023" in console_out
    assert "[MEDIUM]" in console_out
    assert "THR-000002" in console_out
    assert "EV-000027" in console_out
    assert "HIGH: 1" in console_out
    assert "MEDIUM: 1" in console_out
    assert "[JOCKY] Threat analysis completed." in console_out


def test_threat_report_empty():
    result = DetectionResult(
        hostname="CLEAN-HOST",
        findings=[],
        summary={"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
    )

    report = ThreatReport(result)
    console_out = report.format_console()

    assert "Host: CLEAN-HOST" in console_out
    assert "No suspicious indicators identified." in console_out
    assert "CRITICAL: 0" in console_out
