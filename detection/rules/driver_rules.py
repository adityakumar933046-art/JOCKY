"""
JOCKY Driver Detection Rules.

Analyzes driver evidence for path anomalies, missing binary references,
and vulnerable driver indicators without attempting kernel interaction.
"""

from typing import List, Set
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class DriverPathAnomalyRule(DetectionRule):
    rule_id = "DRIVER-001"
    name = "Driver Path Anomaly"
    category = "DRIVER"
    description = "Detects driver image paths located outside standard operating system driver directories."
    severity = Severity.HIGH

    STANDARD_DRIVER_SUBSTRINGS = [
        "system32\\drivers",
        "system32\\driverstore",
        "syswow64\\drivers",
        "/lib/modules/",
        "/usr/lib/modules/",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        driver_records = self.filter_evidence_by_operation(evidence, "scan_drivers")

        for rec in driver_records:
            drivers = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for d in drivers:
                if not isinstance(d, dict):
                    continue

                path = d.get("path")
                if not path or not isinstance(path, str):
                    continue

                path_lower = path.lower()
                # Check if it has a path and is outside standard directories
                is_standard = any(std in path_lower for std in self.STANDARD_DRIVER_SUBSTRINGS)
                # If path mentions temp, user folders, or appdata
                is_suspicious_path = any(
                    susp in path_lower for susp in ("\\temp\\", "\\tmp\\", "/tmp/", "\\users\\", "\\appdata\\")
                )

                if is_suspicious_path or (not is_standard and not path_lower.startswith("\\systemroot\\")):
                    findings.append(
                        self.create_finding(
                            title="Driver Path Anomaly",
                            description=(
                                f"Driver '{d.get('name')}' specifies a binary path outside standard system driver "
                                f"directories ('{path}'); requires verification."
                            ),
                            affected_object=d.get("name") or path,
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "driver_name": d.get("name"),
                                "display_name": d.get("display_name"),
                                "path": path,
                                "driver_type": d.get("type"),
                            },
                            recommendation="Verify digital signature, publisher, and installation authorization for this driver binary.",
                            severity=Severity.HIGH,
                            confidence=0.86,
                        )
                    )

        return findings


class PotentiallyVulnerableDriverRule(DetectionRule):
    rule_id = "DRIVER-002"
    name = "Potentially Vulnerable Driver"
    category = "DRIVER"
    description = "Checks driver names against known vulnerable driver indicators or reports status availability."
    severity = Severity.MEDIUM

    # Selected well-known vulnerable driver names from public DFIR databases (LOLDrivers)
    KNOWN_VULNERABLE_DRIVERS: Set[str] = {
        "gdrv.sys",
        "procexp152.sys",
        "mhyprot2.sys",
        "dbutil_2_3.sys",
        "rtcore64.sys",
        "cpuz141.sys",
        "atsdio64.sys",
    }

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        driver_records = self.filter_evidence_by_operation(evidence, "scan_drivers")

        for rec in driver_records:
            drivers = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for d in drivers:
                if not isinstance(d, dict):
                    continue

                name = (d.get("name") or "").lower()
                path = (d.get("path") or "").lower()

                matched = None
                for vuln in self.KNOWN_VULNERABLE_DRIVERS:
                    if vuln in name or vuln in path:
                        matched = vuln
                        break

                if matched:
                    findings.append(
                        self.create_finding(
                            title="Potentially Vulnerable Driver",
                            description=(
                                f"Driver '{d.get('name')}' matches known vulnerable driver indicator '{matched}'; "
                                f"investigate potential BYOVD exposure."
                            ),
                            affected_object=d.get("name") or matched,
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "driver_name": d.get("name"),
                                "matched_indicator": matched,
                                "path": d.get("path"),
                                "vulnerability_status": "Known vulnerable driver signature identified in reference list.",
                            },
                            recommendation="Check if driver is authorized and confirm that latest patched version is deployed.",
                            severity=Severity.HIGH,
                            confidence=0.90,
                        )
                    )

        return findings
