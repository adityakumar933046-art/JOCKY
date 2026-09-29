"""
JOCKY Memory Indicator Detection Rules.

Analyzes memory metrics and indicators collected during triage without allocating
or interacting with live memory spaces.
"""

from typing import List
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class SuspiciousMemoryIndicatorRule(DetectionRule):
    rule_id = "MEM-001"
    name = "Suspicious Executable Memory Indicator"
    category = "MEMORY"
    description = "Analyzes memory allocation ratios, excessive pagefile pressure, or reported anomalous memory structures."
    severity = Severity.LOW

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        mem_records = self.filter_evidence_by_operation(evidence, "analyze_memory")

        for rec in mem_records:
            items = rec.data if isinstance(rec.data, dict) else {}
            # Check for memory saturation / exhaustion anomalies
            load = items.get("memory_load_percent")
            if isinstance(load, (int, float)) and load > 98:
                findings.append(
                    self.create_finding(
                        title="Suspicious Executable Memory Indicator",
                        description=(
                            f"Host system memory load is critically elevated ({load}% utilized); "
                            f"may indicate denial of service, memory leakage, or active dump attempt."
                        ),
                        affected_object="PhysicalMemory",
                        hostname=rec.hostname,
                        evidence_ids=[rec.evidence_id],
                        indicators={
                            "memory_load_percent": load,
                            "available_physical_bytes": items.get("available_physical_bytes"),
                            "total_physical_bytes": items.get("total_physical_bytes"),
                        },
                        recommendation="Identify top process memory consumers to determine if resource consumption is legitimate.",
                        severity=Severity.LOW,
                        confidence=0.70,
                    )
                )

            # Check if suspicious executable/writable regions were flagged in items
            suspicious_regions = items.get("suspicious_regions", [])
            if isinstance(suspicious_regions, list) and suspicious_regions:
                for region in suspicious_regions:
                    findings.append(
                        self.create_finding(
                            title="Suspicious Executable Memory Indicator",
                            description="Anomalous executable memory permissions (e.g. RWX) identified in memory structure.",
                            affected_object=str(region),
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={"region_info": region},
                            recommendation="Perform targeted memory inspection on flagged region.",
                            severity=Severity.HIGH,
                            confidence=0.92,
                        )
                    )

        return findings
