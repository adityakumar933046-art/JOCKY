"""
JOCKY Process Detection Rules.

Analyzes process evidence for anomalous parent-child relationships,
unusual execution locations, and missing executable metadata.
"""

from typing import List, Dict, Set
from pathlib import Path
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class SuspiciousProcessRelationshipRule(DetectionRule):
    rule_id = "PROC-001"
    name = "Suspicious Process Relationship"
    category = "PROCESS"
    description = "Detects anomalous or unexpected parent-child process relationships."
    severity = Severity.HIGH

    # Known suspicious parent -> child relationships commonly seen in attacks
    # e.g., web servers or office binaries spawning shells or script interpreters
    SUSPICIOUS_SPAWNS: Dict[str, Set[str]] = {
        "powershell.exe": {"whoami.exe", "net.exe", "net1.exe", "nltest.exe", "certutil.exe", "bitsadmin.exe"},
        "cmd.exe": {"powershell.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe"},
        "w3wp.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash"},
        "httpd": {"sh", "bash", "python", "perl"},
        "nginx": {"sh", "bash", "python", "perl"},
        "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    }

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        proc_records = self.filter_evidence_by_operation(evidence, "scan_processes")

        for rec in proc_records:
            procs = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            # Map PID -> process for lookup
            pid_map = {p.get("pid"): p for p in procs if isinstance(p, dict) and p.get("pid") is not None}

            for p in procs:
                if not isinstance(p, dict):
                    continue

                parent_pid = p.get("parent_pid")
                parent = pid_map.get(parent_pid)
                if not parent:
                    continue

                parent_name = (parent.get("name") or "").lower()
                child_name = (p.get("name") or "").lower()

                # Check known suspicious pattern
                if parent_name in self.SUSPICIOUS_SPAWNS:
                    flagged_children = self.SUSPICIOUS_SPAWNS[parent_name]
                    if child_name in flagged_children or (
                        parent_name in ("powershell.exe", "cmd.exe") and child_name.endswith(".exe") and child_name not in ("conhost.exe", "cmd.exe", "powershell.exe")
                    ):
                        findings.append(
                            self.create_finding(
                                title="Suspicious Process Relationship",
                                description="Potentially suspicious process relationship detected; investigate process ancestry and executable origin.",
                                affected_object=child_name,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "parent_pid": parent_pid,
                                    "parent_name": parent.get("name"),
                                    "child_pid": p.get("pid"),
                                    "child_name": p.get("name"),
                                    "child_executable": p.get("executable"),
                                },
                                recommendation="Review process ancestry and executable origin.",
                                severity=Severity.HIGH,
                                confidence=0.91,
                            )
                        )

        return findings


class UnusualExecutableLocationRule(DetectionRule):
    rule_id = "PROC-002"
    name = "Executable from Unusual Location"
    category = "PROCESS"
    description = "Detects processes executing from temporary, user-writable, or staging directories."
    severity = Severity.MEDIUM

    SUSPICIOUS_DIR_PATTERNS = [
        "\\temp\\",
        "\\tmp\\",
        "/tmp/",
        "/var/tmp/",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "\\downloads\\",
        "/downloads/",
        "/dev/shm/",
    ]

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        proc_records = self.filter_evidence_by_operation(evidence, "scan_processes")

        for rec in proc_records:
            procs = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for p in procs:
                if not isinstance(p, dict):
                    continue

                exe_path = p.get("executable")
                if not exe_path or not isinstance(exe_path, str):
                    continue

                path_lower = exe_path.lower()
                for pattern in self.SUSPICIOUS_DIR_PATTERNS:
                    if pattern in path_lower:
                        findings.append(
                            self.create_finding(
                                title="Executable from Unusual Location",
                                description=f"Process executing from a temporary or staging directory ({pattern}); requires investigation.",
                                affected_object=p.get("name") or exe_path,
                                hostname=rec.hostname,
                                evidence_ids=[rec.evidence_id],
                                indicators={
                                    "pid": p.get("pid"),
                                    "name": p.get("name"),
                                    "executable": exe_path,
                                    "matched_pattern": pattern,
                                },
                                recommendation="Verify binary authenticity and reason for execution from staging directory.",
                                severity=Severity.MEDIUM,
                                confidence=0.88,
                            )
                        )
                        break

        return findings


class MissingProcessMetadataRule(DetectionRule):
    rule_id = "PROC-003"
    name = "Process with Inaccessible Executable Metadata"
    category = "PROCESS"
    description = "Detects userland processes where executable path or binary metadata could not be retrieved."
    severity = Severity.LOW

    # Standard kernel / system identifiers that naturally lack userland executables
    EXCLUDED_PIDS = {0, 4}
    EXCLUDED_NAMES = {"system", "[system process]", "registry", "memcompression", "secure system"}

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        proc_records = self.filter_evidence_by_operation(evidence, "scan_processes")

        for rec in proc_records:
            procs = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for p in procs:
                if not isinstance(p, dict):
                    continue

                pid = p.get("pid")
                name = (p.get("name") or "").lower()

                if pid in self.EXCLUDED_PIDS or name in self.EXCLUDED_NAMES:
                    continue

                # Flag if non-system process has ACCESS_DENIED or missing executable path
                if p.get("error") == "ACCESS_DENIED" or (p.get("executable") is None and pid and pid > 100):
                    findings.append(
                        self.create_finding(
                            title="Process with Inaccessible Executable Metadata",
                            description="Userland process metadata could not be retrieved during forensic collection; review process privileges and security context.",
                            affected_object=p.get("name") or f"PID {pid}",
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "pid": pid,
                                "name": p.get("name"),
                                "error": p.get("error"),
                            },
                            recommendation="Review process privileges and evaluate whether elevated investigation is required.",
                            severity=Severity.LOW,
                            confidence=0.72,
                        )
                    )

        return findings
