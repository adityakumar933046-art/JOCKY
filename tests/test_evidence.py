"""
Unit tests for JOCKY Evidence Models, Serializer, Store, and Interpreter integration.
"""

import json
from pathlib import Path
from evidence.models import EvidenceRecord
from evidence.serializer import EvidenceSerializer
from evidence.store import EvidenceStore
from compiler.ir import IRInstruction
from runtime.interpreter import ForensicInterpreter
from runtime.collectors.windows import WindowsCollector


def test_evidence_record_creation():
    rec = EvidenceRecord(
        hostname="DFIR-WS-01",
        operating_system="Windows",
        collector="WindowsCollector",
        operation="processes",
        collection_status="success",
        data=[{"pid": 100, "name": "explorer.exe"}],
    )

    assert rec.evidence_id.startswith("EV-")
    assert rec.hostname == "DFIR-WS-01"
    assert rec.data[0]["name"] == "explorer.exe"

    d = rec.to_dict()
    assert d["evidence_id"] == rec.evidence_id
    assert d["operation"] == "processes"


def test_evidence_serializer_json():
    rec = EvidenceRecord(
        hostname="DFIR-WS-01",
        operating_system="Linux",
        collector="LinuxCollector",
        operation="network",
        data={"connections": 42},
    )
    json_str = EvidenceSerializer.to_json(rec)
    parsed = json.loads(json_str)

    assert parsed["evidence_id"] == rec.evidence_id
    assert parsed["data"]["connections"] == 42


def test_evidence_store_file_creation(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    rec = EvidenceRecord(
        hostname="FORENSIC-01",
        operating_system="Windows",
        collector="WindowsCollector",
        operation="system_info",
        data={"arch": "x86_64"},
    )

    saved_path = store.save(rec)
    assert saved_path.exists()
    assert saved_path.name == f"{rec.evidence_id}.json"

    content = json.loads(saved_path.read_text(encoding="utf-8"))
    assert content["evidence_id"] == rec.evidence_id
    assert content["data"]["arch"] == "x86_64"


def test_evidence_store_report_consolidation(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    r1 = EvidenceRecord(operation="system_info", data={"info": 1})
    r2 = EvidenceRecord(operation="processes", data={"count": 5})

    report_path = store.save_report("sample_investigation", [r1, r2])
    assert report_path.exists()
    assert report_path.name == "sample_investigation.json"

    content = json.loads(report_path.read_text(encoding="utf-8"))
    assert content["report_name"] == "sample_investigation"
    assert content["total_records"] == 2


def test_interpreter_simulation_mode_unchanged(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    interpreter = ForensicInterpreter(mode="simulation", evidence_store=store, quiet=True)
    instructions = [
        IRInstruction(opcode="SYSTEM_INFO"),
        IRInstruction(opcode="SCAN", target="PROCESSES"),
        IRInstruction(opcode="REPORT", target="test_report"),
    ]

    result = interpreter.execute(instructions)
    assert result.success is True
    assert result.mode == "simulation"
    assert len(result.records) == 0
    # In simulation mode, no evidence files should be generated
    assert len(list(tmp_path.glob("EV-*.json"))) == 0


def test_interpreter_real_mode_integration(tmp_path):
    store = EvidenceStore(output_dir=str(tmp_path))
    # Run with small subset of instructions
    instructions = [
        IRInstruction(opcode="SYSTEM_INFO"),
        IRInstruction(opcode="SCAN", target="FILES"),
        IRInstruction(opcode="REPORT", target="test_real_report"),
    ]
    interpreter = ForensicInterpreter(mode="real", evidence_store=store, quiet=True)
    result = interpreter.execute(instructions)

    assert result.success is True
    assert result.mode == "real"
    assert len(result.records) == 2  # SYSTEM_INFO and SCAN FILES generate records
    assert len(list(tmp_path.glob("EV-*.json"))) == 2
    assert (tmp_path / "test_real_report.json").exists()
