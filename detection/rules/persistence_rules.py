"""
JOCKY Persistence Detection Rules.

Analyzes persistence evidence (Registry Run keys, startup directories, cron entries)
for suspicious staging locations, script executions, or unusual autorun entries.
"""

from typing import List
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class SuspiciousPersistenceLocationRule(DetectionRule):
    rule_id = "PERSIST-001"
    name = "Potentially Suspicious Persistence Entry"
    category = "PERSISTENCE"
    description = "Detects persistence entries executing from temporary directories or invoking script engines."
    severity = Severity.HIGH

    SUSPICIOUS_TARGET_PATTERNS = [
        "\\temp\\",
        "\\tmp\\",
        "/tmp/",
        "/var/tmp/",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "\\downloads\\",
        "powershell",
        "cmd.exe /c",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "bitsadmin",
        "certutil",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        persist_records = self.filter_evidence_by_operation(evidence, "analyze_persistence")

        for rec in persist_records:
            items = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for item in items:
                if not isinstance(item, dict):
                    continue

                cmd = item.get("target_command") or ""
                cmd_lower = cmd.lower()

                for pattern in self.SUSPICIOUS_TARGET_PATTERNS:
                    if pattern in cmd_lower:
                        findings.append(
                            self.create_finding(
                                title="Potentially Suspicious Persistence Entry",
                                description=(
                                    f"Persistence entry '{item.get('entry_name')}' references a suspicious "
                                    f"target or execution pattern ('{pattern}'); requires investigation."
                                ),
                                affected_object=item.get("entry_name") or cmd,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "persistence_type": item.get("type"),
                                    "location": item.get("location"),
                                    "entry_name": item.get("entry_name"),
                                    "command": cmd,
                                    "matched_pattern": pattern,
                                },
                                recommendation="Review legitimacy of autorun entry and inspect target binary or script.",
                                severity=Severity.HIGH,
                                confidence=0.89,
                            )
                        )
                        break

        return findings


class ShellProfilePersistenceRule(DetectionRule):
    rule_id = "PERSIST-002"
    name = "Shell Profile Persistence Indicator"
    category = "PERSISTENCE"
    description = "Detects persistence hooks located in user or system shell environment initialization profiles."
    severity = Severity.MEDIUM

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        persist_records = self.filter_evidence_by_operation(evidence, "analyze_persistence")

        for rec in persist_records:
            items = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for item in items:
                if not isinstance(item, dict):
                    continue

                if item.get("type") == "ShellProfile":
                    findings.append(
                        self.create_finding(
                            title="Shell Profile Persistence Indicator",
                            description="User shell environment profile detected in persistence configuration; review for unauthorized environment modifications.",
                            affected_object=item.get("location", "ShellProfile"),
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "location": item.get("location"),
                                "type": item.get("type"),
                            },
                            recommendation="Inspect shell profile contents for anomalous commands or aliased utilities.",
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                        )
                    )

        return findings
