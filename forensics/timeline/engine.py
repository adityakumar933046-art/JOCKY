"""
JOCKY Forensic Chronological Timeline Engine.
Aggregates, standardizes, filters, and correlates forensic events across endpoints
into a unified chronological master investigation timeline.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional
import uuid

from forensics.timeline.models import TimelineEvent
from forensics.normalization.models import NormalizedArtifact, NormalizedArtifactType


class TimelineEngine:
    def build_timeline(
        self,
        artifacts: Optional[List[NormalizedArtifact]] = None,
        findings: Optional[List[Any]] = None,
        evidence_records: Optional[List[Any]] = None,
        notes: Optional[List[Any]] = None,
        investigation_id: Optional[str] = None,
        organization_id: str = "org-default",
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        search_query: Optional[str] = None,
        sort_asc: bool = True,
    ) -> List[TimelineEvent]:
        """Generate a unified chronological timeline with multi-dimensional filtering."""
        events: List[TimelineEvent] = []

        # 1. Process Normalized Artifacts
        if artifacts:
            for art in artifacts:
                event = self._artifact_to_event(art, investigation_id, organization_id)
                if event:
                    events.append(event)

        # 2. Process Threat Findings
        if findings:
            for f in findings:
                # Handle both SQLAlchemy model or dict
                fid = getattr(f, "finding_id", None) or f.get("finding_id", "")
                ts = getattr(f, "timestamp", None) or f.get("timestamp")
                if isinstance(ts, datetime):
                    ts = ts.isoformat()
                elif not ts:
                    ts = datetime.now(timezone.utc).isoformat()

                title = getattr(f, "title", None) or f.get("title", "Threat Detected")
                fsev = getattr(f, "severity", None) or f.get("severity", "HIGH")
                fcat = getattr(f, "category", None) or f.get("category", "THREAT")
                desc = getattr(f, "description", None) or f.get("description", "")
                ag_id = getattr(f, "agent_id", None) or f.get("agent_id", "")
                aff = getattr(f, "affected_object", None) or f.get("affected_object", "")

                events.append(TimelineEvent(
                    event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    timestamp=str(ts),
                    event_type="THREAT_DETECTED",
                    category="THREAT",
                    severity=str(fsev).upper(),
                    title=f"Finding: {title}",
                    description=f"{desc} (Target: {aff})" if aff else str(desc),
                    source_id=str(fid),
                    source_type="finding",
                    agent_id=str(ag_id),
                    hostname="",
                    indicators=[aff] if aff else [],
                    metadata={"category": fcat},
                ))

        # 3. Process Evidence Records
        if evidence_records:
            for ev in evidence_records:
                eid = getattr(ev, "evidence_id", None) or ev.get("evidence_id", "")
                ts = getattr(ev, "timestamp", None) or ev.get("timestamp")
                if isinstance(ts, datetime):
                    ts = ts.isoformat()
                elif not ts:
                    ts = datetime.now(timezone.utc).isoformat()

                op = getattr(ev, "operation", None) or ev.get("operation", "collection")
                host = getattr(ev, "hostname", None) or ev.get("hostname", "")
                ag_id = getattr(ev, "agent_id", None) or ev.get("agent_id", "")

                events.append(TimelineEvent(
                    event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    timestamp=str(ts),
                    event_type="EVIDENCE_CAPTURED",
                    category="SYSTEM",
                    severity="INFO",
                    title=f"Forensic Evidence Collected: {op}",
                    description=f"Evidence {eid} collected on host '{host}' via {op}.",
                    source_id=str(eid),
                    source_type="evidence",
                    agent_id=str(ag_id),
                    hostname=str(host),
                    metadata={"operation": op},
                ))

        # 4. Process Notes
        if notes:
            for n in notes:
                nid = getattr(n, "note_id", None) or n.get("note_id", "")
                ts = getattr(n, "created_at", None) or n.get("created_at")
                if isinstance(ts, datetime):
                    ts = ts.isoformat()
                elif not ts:
                    ts = datetime.now(timezone.utc).isoformat()

                author = getattr(n, "author_name", None) or n.get("author_name", "Analyst")
                content = getattr(n, "content", None) or n.get("content", "")

                events.append(TimelineEvent(
                    event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    investigation_id=investigation_id,
                    timestamp=str(ts),
                    event_type="INVESTIGATION_NOTE",
                    category="NOTE",
                    severity="INFO",
                    title=f"Analyst Note by {author}",
                    description=str(content),
                    source_id=str(nid),
                    source_type="note",
                    metadata={"author": author},
                ))

        # Apply Filters
        filtered = events
        if category:
            cat_lower = category.lower()
            filtered = [e for e in filtered if e.category.lower() == cat_lower]
        if severity:
            sev_upper = severity.upper()
            filtered = [e for e in filtered if e.severity.upper() == sev_upper]
        if agent_id:
            filtered = [e for e in filtered if e.agent_id == agent_id]
        if search_query:
            q = search_query.lower()
            filtered = [
                e for e in filtered
                if q in e.title.lower()
                or q in e.description.lower()
                or any(q in ind.lower() for ind in e.indicators)
            ]

        # Chronological Sort
        filtered.sort(key=lambda e: e.timestamp, reverse=not sort_asc)
        return filtered

    def _artifact_to_event(
        self,
        art: NormalizedArtifact,
        investigation_id: Optional[str],
        organization_id: str,
    ) -> Optional[TimelineEvent]:
        """Convert a normalized artifact into a structured timeline event."""
        attrs = art.normalized_attributes or {}
        atype = art.artifact_type
        ts = art.timestamp or datetime.now(timezone.utc).isoformat()

        if atype == NormalizedArtifactType.PROCESS.value:
            pname = attrs.get("name") or "Unknown"
            pid = attrs.get("pid", 0)
            return TimelineEvent(
                event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                organization_id=organization_id,
                investigation_id=investigation_id,
                timestamp=ts,
                event_type="PROCESS_START",
                category="PROCESS",
                severity="INFO",
                title=f"Process Running: {pname} (PID: {pid})",
                description=f"Path: {attrs.get('path', 'N/A')}, CmdLine: {attrs.get('cmdline', 'N/A')}",
                source_id=art.artifact_id,
                source_type="artifact",
                agent_id=art.agent_id,
                hostname=art.hostname,
                indicators=art.indicators,
                metadata={"pid": pid, "ppid": attrs.get("ppid")},
            )

        elif atype == NormalizedArtifactType.NETWORK.value:
            rip = attrs.get("remote_ip") or ""
            rport = attrs.get("remote_port", 0)
            proto = attrs.get("protocol", "TCP")
            pname = attrs.get("process_name") or f"PID {attrs.get('pid', 'N/A')}"
            sev = "HIGH" if rport in [4444, 1337, 8888, 9001] else "INFO"
            return TimelineEvent(
                event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                organization_id=organization_id,
                investigation_id=investigation_id,
                timestamp=ts,
                event_type="NETWORK_CONNECTION",
                category="NETWORK",
                severity=sev,
                title=f"Network Socket: {pname} -> {rip}:{rport} ({proto})",
                description=f"Connection state: {attrs.get('state', 'UNKNOWN')}, Local: {attrs.get('local_ip')}:{attrs.get('local_port')}",
                source_id=art.artifact_id,
                source_type="artifact",
                agent_id=art.agent_id,
                hostname=art.hostname,
                indicators=art.indicators,
                metadata={"remote_ip": rip, "remote_port": rport, "protocol": proto},
            )

        elif atype == NormalizedArtifactType.FILE.value:
            fpath = attrs.get("path") or attrs.get("filename") or "Unknown"
            return TimelineEvent(
                event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                organization_id=organization_id,
                investigation_id=investigation_id,
                timestamp=ts,
                event_type="FILE_OBSERVED",
                category="FILE",
                severity="INFO",
                title=f"File Artifact: {attrs.get('filename', fpath)}",
                description=f"Path: {fpath}, SHA256: {attrs.get('sha256', 'N/A')}, Size: {attrs.get('size_bytes', 0)} bytes",
                source_id=art.artifact_id,
                source_type="artifact",
                agent_id=art.agent_id,
                hostname=art.hostname,
                indicators=art.indicators,
                metadata={"path": fpath},
            )

        elif atype == NormalizedArtifactType.SERVICE.value:
            sname = attrs.get("service_name") or "Unknown"
            return TimelineEvent(
                event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                organization_id=organization_id,
                investigation_id=investigation_id,
                timestamp=ts,
                event_type="SERVICE_REGISTERED",
                category="SERVICE",
                severity="INFO",
                title=f"Service Active: {sname}",
                description=f"Display Name: {attrs.get('display_name')}, BinPath: {attrs.get('binpath', 'N/A')}",
                source_id=art.artifact_id,
                source_type="artifact",
                agent_id=art.agent_id,
                hostname=art.hostname,
                indicators=art.indicators,
            )

        elif atype == NormalizedArtifactType.PERSISTENCE.value:
            pname = attrs.get("name") or attrs.get("entry_type") or "Persistence Item"
            return TimelineEvent(
                event_id=f"TLE-{uuid.uuid4().hex[:8].upper()}",
                organization_id=organization_id,
                investigation_id=investigation_id,
                timestamp=ts,
                event_type="PERSISTENCE_INSTALLED",
                category="PERSISTENCE",
                severity="MEDIUM",
                title=f"Persistence Configured: {pname}",
                description=f"Type: {attrs.get('entry_type')}, Target: {attrs.get('target_path') or attrs.get('command')}",
                source_id=art.artifact_id,
                source_type="artifact",
                agent_id=art.agent_id,
                hostname=art.hostname,
                indicators=art.indicators,
            )

        return None


default_timeline_engine = TimelineEngine()
