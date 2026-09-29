"""
JOCKY Service + Process Correlation Rule.
Correlates installed operating system services with running processes and binary executables.
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


class ServiceProcessCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-SVC-PROC"
    name = "Service and Process Correlation"
    description = "Links OS services to their active running instances and registered binary executables."

    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        relationships: List[ArtifactRelationship] = []
        correlated_findings: List[CorrelatedFinding] = []

        services = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.SERVICE.value]
        procs = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.PROCESS.value]

        procs_by_pid = {}
        procs_by_name = {}
        for p in procs:
            pid = p.normalized_attributes.get("pid", 0)
            if pid:
                procs_by_pid[(p.agent_id, pid)] = p
            name = (p.normalized_attributes.get("name") or "").lower()
            if name:
                procs_by_name[(p.agent_id, name)] = p

        for svc in services:
            sattrs = svc.normalized_attributes
            spid = sattrs.get("pid", 0)
            binpath = (sattrs.get("binpath") or "").lower()
            sname = (sattrs.get("service_name") or "").lower()

            matched_proc = None
            if spid and (svc.agent_id, spid) in procs_by_pid:
                matched_proc = procs_by_pid[(svc.agent_id, spid)]
            elif binpath:
                for (ag_id, p_name), p in procs_by_name.items():
                    if ag_id == svc.agent_id and (p_name in binpath or binpath in p.normalized_attributes.get("path", "").lower()):
                        matched_proc = p
                        break

            if matched_proc:
                relationships.append(ArtifactRelationship(
                    relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    source_artifact_id=svc.artifact_id,
                    target_artifact_id=matched_proc.artifact_id,
                    relationship_type=RelationshipType.SPAWNED.value,
                    confidence=0.95,
                    evidence_ids=list(set(filter(None, [svc.evidence_id, matched_proc.evidence_id]))),
                    metadata={
                        "service_name": sattrs.get("service_name"),
                        "display_name": sattrs.get("display_name"),
                        "pid": matched_proc.normalized_attributes.get("pid"),
                    },
                ))

        return relationships, correlated_findings, []
