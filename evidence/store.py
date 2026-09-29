"""
JOCKY Local Evidence Store.

Safely stores collected forensic evidence into isolated JSON files.
Strictly write-only with respect to evidence targets: never alters host system artifacts.
"""

import os
from pathlib import Path
from typing import List, Optional
from evidence.models import EvidenceRecord
from evidence.serializer import EvidenceSerializer


class EvidenceStore:
    def __init__(self, output_dir: str = "evidence_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, record: EvidenceRecord) -> Path:
        """Save a single evidence record to a standalone JSON file."""
        filename = f"{record.evidence_id}.json"
        filepath = self.output_dir / filename
        data_json = EvidenceSerializer.to_json(record)
        filepath.write_text(data_json, encoding="utf-8")
        return filepath

    def save_report(self, report_name: str, records: List[EvidenceRecord]) -> Path:
        """Consolidate multiple evidence records into a single named report JSON."""
        # Sanitize report filename
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in report_name)
        if not safe_name.endswith(".json"):
            filename = f"{safe_name}.json"
        else:
            filename = safe_name

        filepath = self.output_dir / filename
        report_data = {
            "report_name": report_name,
            "total_records": len(records),
            "records": [rec.to_dict() for rec in records],
        }
        filepath.write_text(EvidenceSerializer.to_json(report_data), encoding="utf-8")
        return filepath

    def list_evidence_files(self) -> List[Path]:
        """List all saved evidence files in the store."""
        return sorted(list(self.output_dir.glob("EV-*.json")))
