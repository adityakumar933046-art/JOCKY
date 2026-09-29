"""
JOCKY Process + File Correlation Rule.
Correlates process execution with filesystem artifacts, binary paths, hashes, and parent-child trees.
"""

from typing import Any, List, Tuple
import uuid

from forensics.correlation.rules.base import BaseCorrelationRule
from forensics.normalization.models import (
    NormalizedArtifact,
    NormalizedArtifactType,
    ArtifactRelationship,
    RelationshipType,
)
from forensics.indicators.models import Indicator
from forensics.correlation.models import CorrelatedFinding, CrossSystemCorrelation


class ProcessFileCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-PROC-FILE"
    name = "Process, File, and Parent-Child Correlation"
    description = "Links running processes to their binary files on disk and establishes parent-child ancestry."

    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        relationships: List[ArtifactRelationship] = []
        correlated_findings: List[CorrelatedFinding] = []

        procs = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.PROCESS.value]
        files = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.FILE.value]

        # 1. Establish Parent-Child Process Relationships
        proc_by_pid = {}
        for p in procs:
            pid = p.normalized_attributes.get("pid", 0)
            if pid and pid > 0:
                proc_by_pid[(p.agent_id, pid)] = p

        for child in procs:
            ppid = child.normalized_attributes.get("ppid", 0)
            parent = proc_by_pid.get((child.agent_id, ppid))
            if parent and parent.artifact_id != child.artifact_id:
                relationships.append(ArtifactRelationship(
                    relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    source_artifact_id=parent.artifact_id,
                    target_artifact_id=child.artifact_id,
                    relationship_type=RelationshipType.PARENT_OF.value,
                    confidence=1.0,
                    evidence_ids=list(set(filter(None, [parent.evidence_id, child.evidence_id]))),
                    metadata={
                        "parent_name": parent.normalized_attributes.get("name"),
                        "child_name": child.normalized_attributes.get("name"),
                        "parent_pid": ppid,
                        "child_pid": child.normalized_attributes.get("pid"),
                    },
                ))

        # 2. Correlate Process executable with File on disk
        files_by_path = {}
        for f in files:
            fpath = (f.normalized_attributes.get("path") or "").lower().strip()
            if fpath:
                files_by_path[(f.agent_id, fpath)] = f

        for p in procs:
            exe_path = (p.normalized_attributes.get("path") or "").lower().strip()
            matched_file = files_by_path.get((p.agent_id, exe_path))

            if matched_file:
                relationships.append(ArtifactRelationship(
                    relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    source_artifact_id=p.artifact_id,
                    target_artifact_id=matched_file.artifact_id,
                    relationship_type=RelationshipType.EXECUTED_FROM.value,
                    confidence=1.0,
                    evidence_ids=list(set(filter(None, [p.evidence_id, matched_file.evidence_id]))),
                    metadata={
                        "path": exe_path,
                        "process_name": p.normalized_attributes.get("name"),
                        "file_size": matched_file.normalized_attributes.get("size_bytes"),
                    },
                ))

            # Detect processes executing from suspicious paths
            if exe_path and any(s in exe_path for s in ["/tmp", "\\temp\\", "\\appdata\\local\\temp\\"]):
                pname = p.normalized_attributes.get("name", "Unknown")
                correlated_findings.append(CorrelatedFinding(
                    correlation_id=f"CFND-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    title=f"Binary Executed from Transient Directory: {pname}",
                    category="EXECUTION",
                    severity="HIGH",
                    confidence=0.88,
                    description=(
                        f"Process '{pname}' (PID: {p.normalized_attributes.get('pid')}) executed from "
                        f"suspicious temporary location '{exe_path}' on host {p.hostname}."
                    ),
                    artifact_ids=[p.artifact_id] + ([matched_file.artifact_id] if matched_file else []),
                    agent_ids=[p.agent_id],
                ))

        return relationships, correlated_findings, []
