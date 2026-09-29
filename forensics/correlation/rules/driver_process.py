"""
JOCKY Driver + Process/File Correlation Rule.
Correlates loaded kernel drivers with disk binaries, unsigned drivers, and loading processes.
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


class DriverProcessCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-DRV-PROC"
    name = "Driver and Filesystem/Process Correlation"
    description = "Links loaded kernel modules and drivers to their files and flags unsigned driver activity."

    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        relationships: List[ArtifactRelationship] = []
        correlated_findings: List[CorrelatedFinding] = []

        drivers = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.DRIVER.value]
        files = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.FILE.value]

        files_by_path = {}
        for f in files:
            p = (f.normalized_attributes.get("path") or "").lower().strip()
            if p:
                files_by_path[(f.agent_id, p)] = f

        for drv in drivers:
            dattrs = drv.normalized_attributes
            dpath = (dattrs.get("path") or "").lower().strip()
            matched_file = files_by_path.get((drv.agent_id, dpath))

            if matched_file:
                relationships.append(ArtifactRelationship(
                    relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    source_artifact_id=drv.artifact_id,
                    target_artifact_id=matched_file.artifact_id,
                    relationship_type=RelationshipType.LOCATED_AT.value,
                    confidence=1.0,
                    evidence_ids=list(set(filter(None, [drv.evidence_id, matched_file.evidence_id]))),
                    metadata={
                        "driver_name": dattrs.get("driver_name"),
                        "signed": dattrs.get("signed"),
                    },
                ))

            if dattrs.get("signed") is False:
                dname = dattrs.get("driver_name")
                correlated_findings.append(CorrelatedFinding(
                    correlation_id=f"CFND-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    title=f"Unsigned Kernel Driver Loaded: {dname}",
                    category="PERSISTENCE",
                    severity="HIGH",
                    confidence=0.92,
                    description=(
                        f"Unsigned or untrusted kernel driver '{dname}' loaded on host {drv.hostname} "
                        f"(Path: {dattrs.get('path', 'N/A')})."
                    ),
                    artifact_ids=[drv.artifact_id] + ([matched_file.artifact_id] if matched_file else []),
                    agent_ids=[drv.agent_id],
                ))

        return relationships, correlated_findings, []
