"""
JOCKY Threat Report Generator.

Transforms DetectionResult models into structured JSON dossiers
and formatted console summaries.
"""

import json
from pathlib import Path
from typing import Dict, Any, Union

from detection.models import DetectionResult, Finding
from detection.severity import Severity
from evidence.serializer import EvidenceJSONEncoder


class ThreatReport:
    def __init__(self, result: DetectionResult):
        self.result = result

    def to_json(self, indent: int = 2) -> str:
        """Export detection results as a formatted JSON document."""
        return json.dumps(self.result.to_dict(), indent=indent, cls=EvidenceJSONEncoder)

    def save(self, filepath: Union[str, Path]) -> Path:
        """Save JSON threat report to disk."""
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(), encoding="utf-8")
        return target

    def format_console(self) -> str:
        """Render a human-readable threat analysis report for terminal display."""
        lines = [
            "\n[JOCKY THREAT ANALYSIS]\n",
            f"Host: {self.result.hostname}\n",
            "Findings:\n",
        ]

        if not self.result.findings:
            lines.append("No suspicious indicators identified.\n")
        else:
            # Sort findings by severity rank descending (CRITICAL -> INFO)
            sorted_findings = sorted(
                self.result.findings,
                key=lambda f: f.severity.rank if isinstance(f.severity, Severity) else Severity.from_string(str(f.severity)).rank,
                reverse=True,
            )

            for f in sorted_findings:
                sev_val = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).upper()
                lines.append(f"[{sev_val}]")
                lines.append(f"{f.finding_id}")
                lines.append(f"{f.title}\n")
                if f.evidence_ids:
                    lines.append("Evidence:")
                    for eid in f.evidence_ids:
                        lines.append(f"{eid}")
                    lines.append("")

        lines.append("---")
        lines.append("\nSummary:\n")
        for lvl in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            lines.append(f"{lvl}: {self.result.summary.get(lvl, 0)}")

        lines.append("\n[JOCKY] Threat analysis completed.")
        return "\n".join(lines)
