"""
JOCKY Process + Network Correlation Rule.
Correlates process execution artifacts with active network connections and listening sockets.
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


class ProcessNetworkCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-PROC-NET"
    name = "Process and Network Socket Correlation"
    description = "Links running processes to their local listening ports and remote network connections."

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
        nets = [a for a in artifacts if a.artifact_type == NormalizedArtifactType.NETWORK.value]

        # Group procs by (agent_id, pid) and (agent_id, name)
        proc_by_pid = {}
        for p in procs:
            pid = p.normalized_attributes.get("pid", 0)
            if pid and pid > 0:
                proc_by_pid[(p.agent_id, pid)] = p

        for net in nets:
            nattrs = net.normalized_attributes
            n_pid = nattrs.get("pid", 0)
            matched_proc = proc_by_pid.get((net.agent_id, n_pid))

            if matched_proc:
                is_outbound = bool(nattrs.get("remote_ip") and nattrs.get("remote_ip") not in ("0.0.0.0", "127.0.0.1", "::1", ""))
                rel_type = RelationshipType.CONNECTED_TO.value if is_outbound else RelationshipType.LISTENING_ON.value

                rel = ArtifactRelationship(
                    relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    source_artifact_id=matched_proc.artifact_id,
                    target_artifact_id=net.artifact_id,
                    relationship_type=rel_type,
                    confidence=1.0,
                    evidence_ids=list(set(filter(None, [matched_proc.evidence_id, net.evidence_id]))),
                    metadata={
                        "pid": n_pid,
                        "remote_ip": nattrs.get("remote_ip"),
                        "remote_port": nattrs.get("remote_port"),
                        "process_name": matched_proc.normalized_attributes.get("name"),
                    },
                )
                relationships.append(rel)

                # Check for suspicious C2 port or activity
                rport = nattrs.get("remote_port", 0)
                if is_outbound and rport in [4444, 1337, 8888, 9001, 6667, 8080]:
                    pname = matched_proc.normalized_attributes.get("name", "Unknown")
                    rip = nattrs.get("remote_ip")
                    correlated_findings.append(CorrelatedFinding(
                        correlation_id=f"CFND-{uuid.uuid4().hex[:8].upper()}",
                        organization_id=organization_id,
                        title=f"Suspicious Outbound Network Socket established by {pname}",
                        category="COMMAND_AND_CONTROL",
                        severity="HIGH",
                        confidence=0.90,
                        description=(
                            f"Process '{pname}' (PID: {n_pid}) on agent {matched_proc.agent_id} "
                            f"established outbound connection to {rip}:{rport} ({nattrs.get('protocol', 'TCP')})."
                        ),
                        artifact_ids=[matched_proc.artifact_id, net.artifact_id],
                        agent_ids=[matched_proc.agent_id],
                    ))

        return relationships, correlated_findings, []
