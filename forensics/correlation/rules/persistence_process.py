"""
JOCKY Persistence + Process/File Correlation Rule.
Correlates startup items, run keys, cron jobs, and scheduled tasks with processes and filesystem artifacts.
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


class PersistenceProcessCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-PERSIST-PROC"
    name = "Persistence and Process/File Correlation"
    description = "Links persistence mechanisms to active processes and target binary files on disk."

    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        relationships: List[ArtifactRelationship] = []
        correlated_findings: List[CorrelatedFinding] = []

        persistence = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.PERSISTENCE.value]
        procs = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.PROCESS.value]
        files = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.FILE.value]

        for p in persistence:
            pattrs = p.normalized_attributes
            cmd = (pattrs.get("command") or pattrs.get("target_path") or "").lower()
            if not cmd:
                continue

            # Link with active processes
            for pr in procs:
                if pr.agent_id != p.agent_id:
                    continue
                pname = (pr.normalized_attributes.get("name") or "").lower()
                ppath = (pr.normalized_attributes.get("path") or "").lower()
                if (pname and pname in cmd) or (ppath and ppath in cmd):
                    relationships.append(ArtifactRelationship(
                        relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                        organization_id=organization_id,
                        source_artifact_id=p.artifact_id,
                        target_artifact_id=pr.artifact_id,
                        relationship_type=RelationshipType.SPAWNED.value,
                        confidence=0.90,
                        evidence_ids=list(set(filter(None, [p.evidence_id, pr.evidence_id]))),
                        metadata={"entry_type": pattrs.get("entry_type"), "command": cmd},
                    ))

            # Link with files on disk
            for f in files:
                if f.agent_id != p.agent_id:
                    continue
                fpath = (f.normalized_attributes.get("path") or "").lower()
                if fpath and fpath in cmd:
                    relationships.append(ArtifactRelationship(
                        relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                        organization_id=organization_id,
                        source_artifact_id=p.artifact_id,
                        target_artifact_id=f.artifact_id,
                        relationship_type=RelationshipType.ASSOCIATED_WITH.value,
                        confidence=0.95,
                        evidence_ids=list(set(filter(None, [p.evidence_id, f.evidence_id]))),
                        metadata={"entry_type": pattrs.get("entry_type"), "target_file": fpath},
                    ))

        return relationships, correlated_findings, []
