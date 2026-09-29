"""
JOCKY Evidence Serializer.

Serializes EvidenceRecord instances to JSON and human-readable console output.
"""

import json
from datetime import datetime, date
from pathlib import Path
from typing import Any, Union, List
from evidence.models import EvidenceRecord


class EvidenceJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to safely handle timestamps, paths, and arbitrary forensic types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, bytes):
            try:
                return obj.decode("utf-8")
            except UnicodeDecodeError:
                return obj.hex()
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        return super().default(obj)


class EvidenceSerializer:
    """Converts evidence records into various export formats."""

    @staticmethod
    def to_json(evidence: Union[EvidenceRecord, List[EvidenceRecord], dict, list], indent: int = 2) -> str:
        """Serialize evidence records or dictionaries to formatted JSON string."""
        if isinstance(evidence, EvidenceRecord):
            target = evidence.to_dict()
        elif isinstance(evidence, list):
            target = [item.to_dict() if isinstance(item, EvidenceRecord) else item for item in evidence]
        else:
            target = evidence
        return json.dumps(target, indent=indent, cls=EvidenceJSONEncoder)

    @staticmethod
    def format_console(record: EvidenceRecord) -> str:
        """Format an EvidenceRecord into a concise, readable summary for CLI display."""
        items_count = 0
        if isinstance(record.data, list):
            items_count = len(record.data)
        elif isinstance(record.data, dict):
            items_count = len(record.data.get("items", record.data))

        status_flag = "[OK]" if record.collection_status == "success" else f"[{record.collection_status.upper()}]"
        lines = [
            f"Evidence ID: {record.evidence_id} {status_flag}",
            f"Operation  : {record.operation}",
            f"Collector  : {record.collector} ({record.operating_system} on {record.hostname})",
            f"Timestamp  : {record.timestamp}",
            f"Items Count: {items_count}",
        ]
        return "\n".join(lines)
