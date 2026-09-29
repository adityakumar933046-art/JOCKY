"""
Unit tests for all JOCKY Detection Rules using synthetic evidence records.
"""

from evidence.models import EvidenceRecord
from detection.severity import Severity
from detection.rules.process_rules import (
    SuspiciousProcessRelationshipRule,
    UnusualExecutableLocationRule,
    MissingProcessMetadataRule,
)
from detection.rules.persistence_rules import (
    SuspiciousPersistenceLocationRule,
    ShellProfilePersistenceRule,
)
from detection.rules.driver_rules import (
    DriverPathAnomalyRule,
    PotentiallyVulnerableDriverRule,
)
from detection.rules.network_rules import (
    UnusualListeningPortRule,
    UnexpectedNetworkConnectionRule,
    RepeatedOutboundConnectionRule,
)
from detection.rules.memory_rules import (
    SuspiciousMemoryIndicatorRule,
)
from detection.rules.service_rules import (
    ServiceExecutablePathAnomalyRule,
    SuspiciousServiceConfigurationRule,
)
from detection.rules.file_rules import (
    ExecutableInUnusualLocationRule,
    DeceptiveDoubleExtensionRule,
)


# --- PROCESS RULES ---

def test_proc_001_suspicious_relationship():
    rule = SuspiciousProcessRelationshipRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PROC-1",
            operation="scan_processes",
            data=[
                {"pid": 1000, "name": "powershell.exe", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                {"pid": 2000, "parent_pid": 1000, "name": "whoami.exe", "executable": "C:\\Windows\\System32\\whoami.exe"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "PROC-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected_object == "whoami.exe"


def test_proc_001_benign_relationship():
    rule = SuspiciousProcessRelationshipRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PROC-2",
            operation="scan_processes",
            data=[
                {"pid": 400, "name": "services.exe"},
                {"pid": 500, "parent_pid": 400, "name": "svchost.exe"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 0


def test_proc_002_unusual_executable_location():
    rule = UnusualExecutableLocationRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PROC-3",
            operation="scan_processes",
            data=[
                {"pid": 3001, "name": "mal_stage.exe", "executable": "C:\\Users\\victim\\AppData\\Local\\Temp\\mal_stage.exe"},
                {"pid": 3002, "name": "legit.exe", "executable": "C:\\Program Files\\App\\legit.exe"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "PROC-002"
    assert findings[0].severity == Severity.MEDIUM
    assert "AppData\\Local\\Temp" in findings[0].indicators["executable"]


def test_proc_003_missing_metadata_handling():
    rule = MissingProcessMetadataRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PROC-4",
            operation="scan_processes",
            data=[
                {"pid": 0, "name": "[System Process]", "executable": None},
                {"pid": 4, "name": "System", "executable": None, "error": "ACCESS_DENIED"},
                {"pid": 8888, "name": "hidden_user_proc.exe", "executable": None, "error": "ACCESS_DENIED"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    # PID 0 and PID 4 must be excluded to prevent false positives; PID 8888 should be flagged
    assert len(findings) == 1
    assert findings[0].rule_id == "PROC-003"
    assert "hidden_user_proc.exe" in findings[0].affected_object


# --- PERSISTENCE RULES ---

def test_persist_001_suspicious_location():
    rule = SuspiciousPersistenceLocationRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PERSIST-1",
            operation="analyze_persistence",
            data=[
                {
                    "type": "RegistryRunKey",
                    "location": "HKCU_Run",
                    "entry_name": "UpdaterService",
                    "target_command": "C:\\Users\\user\\AppData\\Local\\Temp\\update.exe",
                },
                {
                    "type": "RegistryRunKey",
                    "location": "HKLM_Run",
                    "entry_name": "AudioDriver",
                    "target_command": "C:\\Program Files\\Realtek\\audio.exe",
                },
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "PERSIST-001"
    assert findings[0].affected_object == "UpdaterService"


def test_persist_002_shell_profile():
    rule = ShellProfilePersistenceRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-PERSIST-2",
            operation="analyze_persistence",
            data=[{"type": "ShellProfile", "location": "/home/user/.bashrc"}],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "PERSIST-002"


# --- DRIVER RULES ---

def test_driver_001_path_anomaly():
    rule = DriverPathAnomalyRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-DRV-1",
            operation="scan_drivers",
            data=[
                {"name": "StandardDriver", "path": "C:\\Windows\\System32\\drivers\\std.sys"},
                {"name": "SuspiciousDriver", "path": "C:\\Users\\Public\\mal.sys"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "DRIVER-001"
    assert findings[0].affected_object == "SuspiciousDriver"


def test_driver_002_vulnerable_driver():
    rule = PotentiallyVulnerableDriverRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-DRV-2",
            operation="scan_drivers",
            data=[
                {"name": "gdrv", "path": "C:\\Windows\\System32\\drivers\\gdrv.sys"},
                {"name": "clean_net", "path": "C:\\Windows\\System32\\drivers\\net.sys"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "DRIVER-002"
    assert findings[0].severity == Severity.HIGH


# --- NETWORK RULES ---

def test_net_002_unusual_listening_port():
    rule = UnusualListeningPortRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-NET-1",
            operation="scan_network",
            data=[
                {"state": "LISTENING", "local_port": 80, "protocol": "TCP"},
                {"state": "LISTENING", "local_port": 4444, "protocol": "TCP"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-002"
    assert "4444" in findings[0].affected_object


def test_net_001_unexpected_outbound():
    rule = UnexpectedNetworkConnectionRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-NET-2",
            operation="scan_network",
            data=[
                {"state": "ESTABLISHED", "remote_address": "93.184.216.34", "remote_port": 443},
                {"state": "ESTABLISHED", "remote_address": "198.51.100.22", "remote_port": 1337},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-001"
    assert "1337" in findings[0].affected_object


def test_net_003_repeated_outbound():
    rule = RepeatedOutboundConnectionRule()
    conns = [{"state": "ESTABLISHED", "remote_address": "203.0.113.50", "remote_port": 8080} for _ in range(10)]
    evidence = [
        EvidenceRecord(
            evidence_id="EV-NET-3",
            operation="scan_network",
            data=conns,
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-003"
    assert findings[0].affected_object == "203.0.113.50"


# --- MEMORY RULES ---

def test_mem_001_memory_indicator():
    rule = SuspiciousMemoryIndicatorRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-MEM-1",
            operation="analyze_memory",
            data={"memory_load_percent": 99, "available_physical_bytes": 1000},
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "MEM-001"


# --- SERVICE RULES ---

def test_srv_001_service_path_anomaly():
    rule = ServiceExecutablePathAnomalyRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-SRV-1",
            operation="scan_services",
            data=[
                {"service_name": "NormalSrv", "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
                {"service_name": "BackdoorSrv", "path": "C:\\Users\\John\\AppData\\Local\\Temp\\srv.exe"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "SRV-001"
    assert findings[0].affected_object == "BackdoorSrv"


def test_srv_002_service_configuration():
    rule = SuspiciousServiceConfigurationRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-SRV-2",
            operation="scan_services",
            data=[
                {"service_name": "CmdService", "path": "cmd.exe /c powershell -ExecutionPolicy Bypass"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "SRV-002"


# --- FILE RULES ---

def test_file_001_executable_in_temp():
    rule = ExecutableInUnusualLocationRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-FILE-1",
            operation="scan_files",
            data=[
                {"path": "C:\\Windows\\System32\\cmd.exe", "filename": "cmd.exe", "extension": ".exe"},
                {"path": "C:\\Users\\Public\\mal.exe", "filename": "mal.exe", "extension": ".exe"},
                {"path": "/tmp/payload.elf", "filename": "payload.elf", "extension": ".bin"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    # /tmp/payload.elf has .bin extension and /tmp path, should match
    assert len(findings) >= 1
    assert any(f.rule_id == "FILE-001" for f in findings)


def test_file_002_deceptive_double_extension():
    rule = DeceptiveDoubleExtensionRule()
    evidence = [
        EvidenceRecord(
            evidence_id="EV-FILE-2",
            operation="scan_files",
            data=[
                {"filename": "normal_invoice.pdf", "path": "C:\\Docs\\normal_invoice.pdf"},
                {"filename": "urgent_invoice.pdf.exe", "path": "C:\\Docs\\urgent_invoice.pdf.exe"},
            ],
        )
    ]
    findings = rule.evaluate(evidence)
    assert len(findings) == 1
    assert findings[0].rule_id == "FILE-002"
    assert findings[0].severity == Severity.HIGH
