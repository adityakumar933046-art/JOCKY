"""
JOCKY Service Detection Rules.

Analyzes service configuration evidence for anomalous binary paths,
script wrapper executions, and missing metadata without altering services.
"""

from typing import List
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class ServiceExecutablePathAnomalyRule(DetectionRule):
    rule_id = "SRV-001"
    name = "Service Executable Path Anomaly"
    category = "SERVICE"
    description = "Detects services configured with binaries residing in temporary, user, or non-standard paths."
    severity = Severity.HIGH

    SUSPICIOUS_SERVICE_PATHS = [
        "\\temp\\",
        "\\tmp\\",
        "/tmp/",
        "/var/tmp/",
        "\\users\\",
        "/home/",
        "\\appdata\\",
        "\\downloads\\",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        srv_records = self.filter_evidence_by_operation(evidence, "scan_services")

        for rec in srv_records:
            services = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for s in services:
                if not isinstance(s, dict):
                    continue

                path = s.get("path")
                if not path or not isinstance(path, str):
                    continue

                path_lower = path.lower()
                for pattern in self.SUSPICIOUS_SERVICE_PATHS:
                    if pattern in path_lower:
                        findings.append(
                            self.create_finding(
                                title="Service Executable Path Anomaly",
                                description=(
                                    f"Service '{s.get('service_name')}' binary path targets a user or temporary directory "
                                    f"('{path}'); requires immediate verification."
                                ),
                                affected_object=s.get("service_name") or path,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "service_name": s.get("service_name"),
                                    "display_name": s.get("display_name"),
                                    "path": path,
                                    "start_type": s.get("start_type"),
                                    "matched_pattern": pattern,
                                },
                                recommendation="Inspect service binary, creator account, and creation event in system logs.",
                                severity=Severity.HIGH,
                                confidence=0.91,
                            )
                        )
                        break

        return findings


class SuspiciousServiceConfigurationRule(DetectionRule):
    rule_id = "SRV-002"
    name = "Suspicious Service Configuration"
    category = "SERVICE"
    description = "Detects services that execute arbitrary command interpreters or script hosts."
    severity = Severity.MEDIUM

    SUSPICIOUS_BINARIES = [
        "powershell",
        "cmd.exe /c",
        "cmd.exe /k",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        srv_records = self.filter_evidence_by_operation(evidence, "scan_services")

        for rec in srv_records:
            services = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for s in services:
                if not isinstance(s, dict):
                    continue

                path = s.get("path") or ""
                path_lower = path.lower()

                for bin_name in self.SUSPICIOUS_BINARIES:
                    if bin_name in path_lower:
                        findings.append(
                            self.create_finding(
                                title="Suspicious Service Configuration",
                                description=(
                                    f"Service '{s.get('service_name')}' executes via a script interpreter or shell wrapper "
                                    f"('{bin_name}'); verify operational purpose."
                                ),
                                affected_object=s.get("service_name") or path,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "service_name": s.get("service_name"),
                                    "path": path,
                                    "matched_interpreter": bin_name,
                                },
                                recommendation="Confirm whether script execution within service host is expected and sanctioned.",
                                severity=Severity.MEDIUM,
                                confidence=0.87,
                            )
                        )
                        break

        return findings
