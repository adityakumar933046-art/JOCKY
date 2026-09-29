"""
JOCKY Network Detection Rules.

Analyzes network evidence for suspicious listening sockets, anomalous outbound endpoints,
and repeated destination connections without active probing.
"""

from collections import Counter
from typing import List, Set
from evidence.models import EvidenceRecord
from detection.models import Finding
from detection.severity import Severity
from detection.rules.base import DetectionRule


class UnusualListeningPortRule(DetectionRule):
    rule_id = "NET-002"
    name = "Unusual Listening Port"
    category = "NETWORK"
    description = "Detects sockets listening on non-standard, backdoor-associated, or unexpected ports."
    severity = Severity.MEDIUM

    SUSPICIOUS_LISTENING_PORTS: Set[int] = {
        1337, 31337, 4444, 5555, 6666, 6667, 8888, 9999, 12345, 2323, 44444
    }

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        net_records = self.filter_evidence_by_operation(evidence, "scan_network")

        for rec in net_records:
            conns = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for c in conns:
                if not isinstance(c, dict):
                    continue

                state = c.get("state")
                port = c.get("local_port")

                if state == "LISTENING" and port in self.SUSPICIOUS_LISTENING_PORTS:
                    findings.append(
                        self.create_finding(
                            title="Unusual Listening Port",
                            description=(
                                f"Socket listening on non-standard or commonly targeted port {port}; "
                                f"investigate associated process."
                            ),
                            affected_object=f"Port {port}/{c.get('protocol', 'TCP')}",
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "local_address": c.get("local_address"),
                                "local_port": port,
                                "protocol": c.get("protocol"),
                                "pid": c.get("pid"),
                            },
                            recommendation="Identify the owning process and confirm whether this listening service is authorized.",
                            severity=Severity.MEDIUM,
                            confidence=0.82,
                        )
                    )

        return findings


class UnexpectedNetworkConnectionRule(DetectionRule):
    rule_id = "NET-001"
    name = "Unexpected Network Connection"
    category = "NETWORK"
    description = "Detects active connections to anomalous remote destination ports or unencrypted channels."
    severity = Severity.LOW

    SUSPICIOUS_OUTBOUND_PORTS: Set[int] = {
        4444, 1337, 31337, 6667, 5555, 9001, 9002
    }

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        net_records = self.filter_evidence_by_operation(evidence, "scan_network")

        for rec in net_records:
            conns = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            for c in conns:
                if not isinstance(c, dict):
                    continue

                r_port = c.get("remote_port")
                state = c.get("state")

                if state == "ESTABLISHED" and r_port in self.SUSPICIOUS_OUTBOUND_PORTS:
                    findings.append(
                        self.create_finding(
                            title="Unexpected Network Connection",
                            description=(
                                f"Active outbound connection established to anomalous remote port {r_port}; "
                                f"requires investigation."
                            ),
                            affected_object=f"{c.get('remote_address')}:{r_port}",
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "remote_address": c.get("remote_address"),
                                "remote_port": r_port,
                                "local_address": c.get("local_address"),
                                "local_port": c.get("local_port"),
                                "pid": c.get("pid"),
                            },
                            recommendation="Check the remote IP reputation and inspect the process initiating this outbound traffic.",
                            severity=Severity.MEDIUM,
                            confidence=0.84,
                        )
                    )

        return findings


class RepeatedOutboundConnectionRule(DetectionRule):
    rule_id = "NET-003"
    name = "Repeated Outbound Connection"
    category = "NETWORK"
    description = "Detects high-frequency outbound connections directed to a single external host."
    severity = Severity.LOW

    def evaluate(self, evidence: List[EvidenceRecord]) -> List[Finding]:
        findings: List[Finding] = []
        net_records = self.filter_evidence_by_operation(evidence, "scan_network")

        for rec in net_records:
            conns = rec.data if isinstance(rec.data, list) else rec.data.get("items", [])
            remote_ips = []

            for c in conns:
                if not isinstance(c, dict):
                    continue
                r_addr = c.get("remote_address")
                if r_addr and not r_addr.startswith("127.") and r_addr not in ("0.0.0.0", "*", "::1"):
                    remote_ips.append(r_addr)

            counts = Counter(remote_ips)
            for ip, count in counts.items():
                if count >= 8:  # threshold for repeated connections to same external IP
                    findings.append(
                        self.create_finding(
                            title="Repeated Outbound Connection",
                            description=(
                                f"High concentration of outbound sockets ({count} active connections) directed "
                                f"to remote host '{ip}'; investigate purpose."
                            ),
                            affected_object=ip,
                            hostname=rec.hostname,
                            evidence_ids=[rec.evidence_id],
                            indicators={
                                "remote_address": ip,
                                "connection_count": count,
                            },
                            recommendation="Review the nature of traffic to this destination to rule out beaconing or data exfiltration.",
                            severity=Severity.LOW,
                            confidence=0.76,
                        )
                    )

        return findings
