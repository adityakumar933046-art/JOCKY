"""
JOCKY Forensic Investigation Graph Engine.
Constructs multi-entity relationship graphs connecting endpoints, processes, files,
network sockets, threat findings, and indicators for visual analyst investigation.
"""

from typing import Any, Dict, List, Optional, Set
import uuid

from forensics.graph.models import GraphNode, GraphEdge, InvestigationGraph
from forensics.normalization.models import (
    NormalizedArtifact,
    NormalizedArtifactType,
    ArtifactRelationship,
)
from forensics.indicators.models import Indicator


class GraphEngine:
    def build_graph(
        self,
        investigation_id: str,
        agents: Optional[List[Any]] = None,
        artifacts: Optional[List[NormalizedArtifact]] = None,
        relationships: Optional[List[ArtifactRelationship]] = None,
        indicators: Optional[List[Indicator]] = None,
        findings: Optional[List[Any]] = None,
    ) -> InvestigationGraph:
        """Construct a complete, connected investigation graph."""
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        edge_keys: Set[tuple] = set()

        # 1. Add SYSTEM nodes for Agents
        if agents:
            for ag in agents:
                ag_id = getattr(ag, "agent_id", None) or ag.get("agent_id")
                host = getattr(ag, "hostname", None) or ag.get("hostname", ag_id)
                os_name = getattr(ag, "operating_system", None) or ag.get("operating_system", "Unknown")
                node_id = f"SYS-{ag_id}"
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=f"Host: {host}",
                    type="SYSTEM",
                    severity="INFO",
                    agent_id=str(ag_id),
                    metadata={"hostname": host, "os": os_name},
                )

        # 2. Add Artifact nodes and link to SYSTEM nodes
        if artifacts:
            for art in artifacts:
                attrs = art.normalized_attributes or {}
                atype = art.artifact_type
                label = self._format_artifact_label(atype, attrs)
                sev = "INFO"

                # If network on non-standard port or file in temp, elevate
                if atype == NormalizedArtifactType.NETWORK.value:
                    if attrs.get("remote_port") in [4444, 1337, 8888, 9001]:
                        sev = "HIGH"
                elif atype == NormalizedArtifactType.FILE.value:
                    if any(s in (attrs.get("path") or "").lower() for s in ["/tmp", "\\temp\\"]):
                        sev = "HIGH"

                art_node_id = art.artifact_id
                nodes[art_node_id] = GraphNode(
                    id=art_node_id,
                    label=label,
                    type=atype,
                    severity=sev,
                    agent_id=art.agent_id,
                    metadata=attrs,
                )

                # Connect to Agent SYSTEM node
                if art.agent_id:
                    sys_id = f"SYS-{art.agent_id}"
                    if sys_id in nodes:
                        ekey = (art_node_id, sys_id, "OBSERVED_ON")
                        if ekey not in edge_keys:
                            edge_keys.add(ekey)
                            edges.append(GraphEdge(
                                id=f"EDGE-{uuid.uuid4().hex[:8].upper()}",
                                source=art_node_id,
                                target=sys_id,
                                relationship="OBSERVED_ON",
                                confidence=1.0,
                            ))

        # 3. Add Edges from Artifact Relationships
        if relationships:
            for rel in relationships:
                # Ensure source and target exist in nodes
                if rel.source_artifact_id in nodes and rel.target_artifact_id in nodes:
                    ekey = (rel.source_artifact_id, rel.target_artifact_id, rel.relationship_type)
                    if ekey not in edge_keys:
                        edge_keys.add(ekey)
                        edges.append(GraphEdge(
                            id=f"EDGE-{uuid.uuid4().hex[:8].upper()}",
                            source=rel.source_artifact_id,
                            target=rel.target_artifact_id,
                            relationship=rel.relationship_type,
                            confidence=rel.confidence,
                            evidence_ids=rel.evidence_ids,
                            metadata=rel.metadata,
                        ))

        # 4. Add FINDING nodes and connect to affected artifacts or systems
        if findings:
            for f in findings:
                fid = getattr(f, "finding_id", None) or f.get("finding_id", "")
                title = getattr(f, "title", None) or f.get("title", "Threat Finding")
                fsev = getattr(f, "severity", None) or f.get("severity", "HIGH")
                ag_id = getattr(f, "agent_id", None) or f.get("agent_id")
                aff = getattr(f, "affected_object", None) or f.get("affected_object", "")

                f_node_id = f"FND-{fid}"
                nodes[f_node_id] = GraphNode(
                    id=f_node_id,
                    label=f"Threat: {title}",
                    type="FINDING",
                    severity=str(fsev).upper(),
                    agent_id=str(ag_id) if ag_id else None,
                    metadata={"title": title, "affected_object": aff},
                )

                # Connect to Agent SYSTEM node
                if ag_id:
                    sys_id = f"SYS-{ag_id}"
                    if sys_id in nodes:
                        ekey = (f_node_id, sys_id, "AFFECTS")
                        if ekey not in edge_keys:
                            edge_keys.add(ekey)
                            edges.append(GraphEdge(
                                id=f"EDGE-{uuid.uuid4().hex[:8].upper()}",
                                source=f_node_id,
                                target=sys_id,
                                relationship="AFFECTS",
                                confidence=1.0,
                            ))

                # Connect to artifacts with matching name/pid/path
                if aff and artifacts:
                    for art in artifacts:
                        attrs = art.normalized_attributes or {}
                        if aff in (attrs.get("name"), attrs.get("path"), str(attrs.get("pid")), attrs.get("remote_ip")):
                            ekey = (f_node_id, art.artifact_id, "DETECTED_IN")
                            if ekey not in edge_keys:
                                edge_keys.add(ekey)
                                edges.append(GraphEdge(
                                    id=f"EDGE-{uuid.uuid4().hex[:8].upper()}",
                                    source=f_node_id,
                                    target=art.artifact_id,
                                    relationship="DETECTED_IN",
                                    confidence=0.95,
                                ))

        # 5. Add Key INDICATOR nodes
        if indicators:
            for ind in indicators:
                if ind.severity in ["CRITICAL", "HIGH"] or ind.occurrences > 1:
                    ioc_node_id = f"IOC-{ind.indicator_id}"
                    nodes[ioc_node_id] = GraphNode(
                        id=ioc_node_id,
                        label=f"IOC: {ind.value}",
                        type="INDICATOR",
                        severity=ind.severity,
                        metadata={"indicator_type": ind.indicator_type, "occurrences": ind.occurrences},
                    )

                    # Connect to source artifacts
                    for art_id in ind.source_artifacts:
                        if art_id in nodes:
                            ekey = (ioc_node_id, art_id, "EXTRACTED_FROM")
                            if ekey not in edge_keys:
                                edge_keys.add(ekey)
                                edges.append(GraphEdge(
                                    id=f"EDGE-{uuid.uuid4().hex[:8].upper()}",
                                    source=ioc_node_id,
                                    target=art_id,
                                    relationship="EXTRACTED_FROM",
                                    confidence=1.0,
                                ))

        # Calculate metrics
        entities_by_type: Dict[str, int] = {}
        for n in nodes.values():
            entities_by_type[n.type] = entities_by_type.get(n.type, 0) + 1

        sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        highest = "INFO"
        for n in nodes.values():
            if sev_rank.get(n.severity.upper(), 1) > sev_rank.get(highest, 1):
                highest = n.severity.upper()

        metrics = {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "entities_by_type": entities_by_type,
            "highest_severity": highest,
        }

        return InvestigationGraph(
            investigation_id=investigation_id,
            nodes=list(nodes.values()),
            edges=edges,
            metrics=metrics,
        )

    def _format_artifact_label(self, atype: str, attrs: Dict[str, Any]) -> str:
        """Format an intuitive human-readable node label."""
        if atype == NormalizedArtifactType.PROCESS.value:
            name = attrs.get("name") or "Process"
            pid = attrs.get("pid", "")
            return f"Proc: {name}" + (f" ({pid})" if pid else "")
        elif atype == NormalizedArtifactType.NETWORK.value:
            rip = attrs.get("remote_ip") or "0.0.0.0"
            rport = attrs.get("remote_port") or 0
            return f"Net: {rip}:{rport}"
        elif atype == NormalizedArtifactType.FILE.value:
            return f"File: {attrs.get('filename') or attrs.get('path') or 'File'}"
        elif atype == NormalizedArtifactType.SERVICE.value:
            return f"Svc: {attrs.get('service_name') or 'Service'}"
        elif atype == NormalizedArtifactType.DRIVER.value:
            return f"Driver: {attrs.get('driver_name') or 'Driver'}"
        elif atype == NormalizedArtifactType.PERSISTENCE.value:
            return f"Persist: {attrs.get('name') or attrs.get('entry_type') or 'Startup'}"
        return f"{atype}: {attrs.get('name') or attrs.get('id') or 'Item'}"


default_graph_engine = GraphEngine()
