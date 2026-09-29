"""
JOCKY Cross-System Correlation Rule.
Discovers identical threat indicators, network C2 channels, malware hashes, and artifacts
spanning multiple endpoints across an enterprise network.
"""

from datetime import datetime, timezone
from typing import Any, List, Tuple
import uuid

from forensics.correlation.rules.base import BaseCorrelationRule
from forensics.normalization.models import (
    NormalizedArtifact,
    ArtifactRelationship,
)
from forensics.indicators.models import Indicator, IndicatorType
from forensics.correlation.models import CorrelatedFinding, CrossSystemCorrelation


class CrossSystemCorrelationRule(BaseCorrelationRule):
    rule_id = "CORR-CROSS-SYSTEM"
    name = "Multi-Endpoint Indicator & Campaign Correlation"
    description = "Detects identical indicators (IPs, hashes, binaries) observed across multiple endpoints."

    def correlate(
        self,
        artifacts: List[NormalizedArtifact],
        indicators: List[Indicator],
        findings: List[Any],
        organization_id: str = "org-default",
    ) -> Tuple[List[ArtifactRelationship], List[CorrelatedFinding], List[CrossSystemCorrelation]]:
        cross_correlations: List[CrossSystemCorrelation] = []
        correlated_findings: List[CorrelatedFinding] = []

        # Indicators that should trigger cross-system alerts
        monitored_types = {
            IndicatorType.IPV4.value,
            IndicatorType.SHA256.value,
            IndicatorType.MD5.value,
            IndicatorType.DOMAIN.value,
            IndicatorType.FILE_PATH.value,
            IndicatorType.PROCESS_NAME.value,
        }

        # Benign or standard system indicators to exclude from cross-system alarm
        benign_values = {
            "svchost.exe", "explorer.exe", "services.exe", "systemd", "bash", "sh",
            "python.exe", "python3", "powershell.exe", "cmd.exe", "conhost.exe",
            "127.0.0.1", "0.0.0.0", "::1",
        }

        for ind in indicators:
            if ind.indicator_type not in monitored_types:
                continue
            if ind.value.lower() in benign_values:
                continue

            # Check if observed on 2 or more distinct agents
            agents = list(dict.fromkeys(ind.agents_observed))
            if len(agents) >= 2:
                # Determine severity
                if ind.indicator_type in (IndicatorType.IPV4.value, IndicatorType.SHA256.value, IndicatorType.DOMAIN.value):
                    sev = "CRITICAL"
                else:
                    sev = "HIGH"

                xcorr = CrossSystemCorrelation(
                    correlation_id=f"XCORR-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    indicator_type=ind.indicator_type,
                    indicator_value=ind.value,
                    agents_count=len(agents),
                    agent_ids=agents,
                    first_seen=ind.first_seen,
                    last_seen=ind.last_seen,
                    occurrences=ind.occurrences,
                    severity=sev,
                    details={
                        "source_artifacts_count": len(ind.source_artifacts),
                        "description": f"Indicator {ind.value} detected concurrently across {len(agents)} endpoints.",
                    },
                )
                cross_correlations.append(xcorr)

                # Generate a Correlated Threat Campaign Finding
                correlated_findings.append(CorrelatedFinding(
                    correlation_id=f"CFND-{uuid.uuid4().hex[:8].upper()}",
                    organization_id=organization_id,
                    title=f"Cross-System Campaign: Common {ind.indicator_type} across {len(agents)} Endpoints",
                    category="CAMPAIGN",
                    severity=sev,
                    confidence=0.95,
                    description=(
                        f"Identical forensic indicator ({ind.indicator_type}: '{ind.value}') "
                        f"was observed across multiple distinct endpoints ({', '.join(agents)}). "
                        f"Indicates lateral movement, coordinated compromise, or shared threat infrastructure."
                    ),
                    indicator_ids=[ind.indicator_id],
                    artifact_ids=ind.source_artifacts[:10],
                    agent_ids=agents,
                ))

        return [], correlated_findings, cross_correlations
