"""
Unit tests for the JOCKY Threat Detection Engine.
"""

import pytest
from evidence.models import EvidenceRecord
from detection.engine import ThreatDetectionEngine
from detection.registry import RuleRegistry
from detection.models import Finding
from detection.rules.base import DetectionRule
from detection.severity import Severity


class DummyTestRule(DetectionRule):
    rule_id = "TEST-001"
    name = "Dummy Test Rule"
    category = "TEST"
    severity = Severity.HIGH

    def evaluate(self, evidence):
        findings = []
        for rec in evidence:
            if rec.operation == "test_op":
                findings.append(
                    self.create_finding(
                        title="Dummy Test Finding",
                        description="Detected dummy condition.",
                        affected_object="test_item",
                        hostname=rec.hostname,
                        evidence_ids=[rec.evidence_id],
                        indicators={"raw": rec.data},
                        recommendation="Investigate dummy condition.",
                    )
                )
        return findings


def test_engine_initialization_default_registry():
    engine = ThreatDetectionEngine()
    rules = engine.registry.get_all_rules()
    assert len(rules) >= 14
    rule_ids = [r.rule_id for r in rules]
    assert "PROC-001" in rule_ids
    assert "PERSIST-001" in rule_ids
    assert "DRIVER-001" in rule_ids
    assert "NET-001" in rule_ids


def test_custom_rule_registration_and_execution():
    registry = RuleRegistry()
    registry.register(DummyTestRule())
    engine = ThreatDetectionEngine(registry=registry)

    evidence = [
        EvidenceRecord(evidence_id="EV-100", hostname="HOST-ALPHA", operation="test_op", data={"key": "val"}),
    ]

    result = engine.analyze(evidence)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "TEST-001"
    assert f.evidence_ids == ["EV-100"]
    assert f.hostname == "HOST-ALPHA"
    assert result.summary["HIGH"] == 1


def test_finding_deduplication():
    registry = RuleRegistry()
    registry.register(DummyTestRule())
    engine = ThreatDetectionEngine(registry=registry)

    # Two separate evidence records matching same affected_object for DummyTestRule
    evidence = [
        EvidenceRecord(evidence_id="EV-001", hostname="HOST-BETA", operation="test_op", data={"run": 1}),
        EvidenceRecord(evidence_id="EV-002", hostname="HOST-BETA", operation="test_op", data={"run": 2}),
    ]

    result = engine.analyze(evidence)
    # Finding should be deduplicated to 1 item, with both evidence IDs linked
    assert len(result.findings) == 1
    assert "EV-001" in result.findings[0].evidence_ids
    assert "EV-002" in result.findings[0].evidence_ids


def test_empty_evidence():
    engine = ThreatDetectionEngine()
    result = engine.analyze([])

    assert result.hostname == "UNKNOWN"
    assert len(result.findings) == 0
    assert result.summary == {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }


def test_malformed_evidence_handling():
    engine = ThreatDetectionEngine()
    # Evidence with None data or corrupted items
    evidence = [
        EvidenceRecord(evidence_id="EV-BAD-1", operation="scan_processes", data=None),
        EvidenceRecord(evidence_id="EV-BAD-2", operation="scan_network", data="non-dict string"),
        EvidenceRecord(evidence_id="EV-BAD-3", operation="scan_drivers", data=[123, None, "bad_item"]),
    ]

    # Engine must not raise an unhandled exception
    result = engine.analyze(evidence)
    assert isinstance(result.findings, list)


def test_progress_callback():
    engine = ThreatDetectionEngine()
    called_categories = []

    def on_progress(category, status):
        called_categories.append((category, status))

    engine.analyze([], progress_callback=on_progress)
    assert len(called_categories) >= 7
    cat_names = [c[0] for c in called_categories]
    assert "PROCESS" in cat_names
    assert "PERSISTENCE" in cat_names
    assert "DRIVER" in cat_names
