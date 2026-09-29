"""
JOCKY File Detection Rules.

Analyzes file evidence for executables in temporary paths, deceptive double extensions,
and anomalous file extensions without executing or modifying target files.
"""

from typing import List, Set
from pathlib import Path
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class ExecutableInUnusualLocationRule(DetectionRule):
    rule_id = "FILE-001"
    name = "Executable in Temporary Directory"
    category = "FILE"
    description = "Detects executable binaries located within temporary or user-staging directories."
    severity = Severity.MEDIUM

    EXECUTABLE_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".so", ".bin"
    }

    SUSPICIOUS_PATHS = [
        "\\temp\\",
        "\\tmp\\",
        "/tmp/",
        "/var/tmp/",
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "/downloads/",
        "/dev/shm/",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        file_records = self.filter_evidence_by_operation(evidence, "scan_files")

        for rec in file_records:
            items = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for item in items:
                if not isinstance(item, dict):
                    continue

                path = item.get("path") or ""
                ext = (item.get("extension") or "").lower()
                path_lower = path.lower()

                if ext in self.EXECUTABLE_EXTENSIONS:
                    for spath in self.SUSPICIOUS_PATHS:
                        if spath in path_lower:
                            findings.append(
                                self.create_finding(
                                    title="Executable in Temporary Directory",
                                    description=(
                                        f"Executable file '{item.get('filename')}' residing in staging/temp directory "
                                        f"('{path}'); investigate binary origin."
                                    ),
                                    affected_object=path,
                                    hostname=rec.hostname,
                                    evidence_ids=[rec.evidence_id],
                                    indicators={
                                        "path": path,
                                        "filename": item.get("filename"),
                                        "extension": ext,
                                        "size": item.get("size"),
                                        "sha256": item.get("sha256"),
                                        "matched_directory": spath,
                                    },
                                    recommendation="Hash the file and cross-reference with organizational deployment baselines.",
                                    severity=Severity.MEDIUM,
                                    confidence=0.85,
                                )
                            )
                            break

        return findings


class DeceptiveDoubleExtensionRule(DetectionRule):
    rule_id = "FILE-002"
    name = "Deceptive Double Extension"
    category = "FILE"
    description = "Detects files utilizing deceptive double extensions designed to disguise executable code."
    severity = Severity.HIGH

    DECEPTIVE_PATTERNS = [
        ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
        ".txt.exe", ".jpg.exe", ".png.exe", ".pdf.vbs", ".doc.vbs",
        ".pdf.js", ".txt.ps1", ".pdf.scr",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        file_records = self.filter_evidence_by_operation(evidence, "scan_files")

        for rec in file_records:
            items = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for item in items:
                if not isinstance(item, dict):
                    continue

                filename = (item.get("filename") or "").lower()
                for pat in self.DECEPTIVE_PATTERNS:
                    if filename.endswith(pat):
                        findings.append(
                            self.create_finding(
                                title="Deceptive Double Extension",
                                description=(
                                    f"File '{item.get('filename')}' exhibits a deceptive double extension ({pat}); "
                                    f"indicator of social engineering or masquerading."
                                ),
                                affected_object=item.get("path") or filename,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "filename": item.get("filename"),
                                    "path": item.get("path"),
                                    "pattern": pat,
                                    "sha256": item.get("sha256"),
                                },
                                recommendation="Isolate file and analyze headers to verify true MIME type.",
                                severity=Severity.HIGH,
                                confidence=0.95,
                            )
                        )
                        break

        return findings
