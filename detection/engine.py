"""
JOCKY Threat Detection Engine.

Coordinates the evaluation of collected evidence against detection rules,
deduplicates findings, links evidence chains, and produces structured risk summaries.
"""

from typing import List, Dict, Optional, Callable
from datetime import datetime, timezone

from evidence.models import EvidenceRecord
from detection.models import Finding, DetectionResult
from detection.registry import RuleRegistry
from detection.severity import Severity


class ThreatDetectionEngine:
    def __init__(self, registry: Optional[RuleRegistry] = None):
        self.registry = registry or RuleRegistry.create_default()

    def analyze(
        self,
        evidence: List[EvidenceRecord],
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> DetectionResult:
        """Run all registered rules against the provided evidence records.
        
        Args:
            evidence: List of forensic evidence records.
            progress_callback: Optional callback receiving (category_name, status).
            
        Returns:
            DetectionResult containing deduplicated findings and risk summary.
        """
        raw_findings: List[Finding] = []
        host_name = "UNKNOWN"

        if evidence:
            for rec in evidence:
                if rec.hostname and rec.hostname != "UNKNOWN":
                    host_name = rec.hostname
                    break

        # Group rules by category for organized execution and progress reporting
        categories = ["PROCESS", "PERSISTENCE", "DRIVER", "NETWORK", "MEMORY", "SERVICE", "FILE"]
        
        for cat in categories:
            rules = self.registry.get_rules_by_category(cat)
            for rule in rules:
                try:
                    rule_findings = rule.evaluate(evidence)
                    raw_findings.extend(rule_findings)
                except Exception as e:
                    # Individual rule failures should never crash the engine
                    raw_findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            title=f"Rule Execution Failure ({rule.rule_id})",
                            category=rule.category,
                            severity=Severity.INFO,
                            confidence=1.0,
                            description=f"Rule {rule.name} encountered an error during evaluation: {e}",
                            hostname=host_name,
                            recommendation="Check rule configuration and evidence formatting.",
                        )
                    )

            if progress_callback:
                progress_callback(cat, "completed")

        # Handle any uncategorized or custom rules not in standard 7 categories
        all_rules = self.registry.get_all_rules()
        other_rules = [r for r in all_rules if r.category.upper() not in categories]
        for rule in other_rules:
            try:
                raw_findings.extend(rule.evaluate(evidence))
            except Exception:
                pass

        # Deduplicate findings
        deduped_findings = self._deduplicate(raw_findings)

        # Calculate risk summary
        summary = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }
        for f in deduped_findings:
            sev_str = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).upper()
            if sev_str in summary:
                summary[sev_str] += 1
            else:
                summary["INFO"] += 1

        return DetectionResult(
            hostname=host_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            findings=deduped_findings,
            summary=summary,
        )

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings based on (rule_id, affected_object)."""
        seen = set()
        unique: List[Finding] = []

        for f in findings:
            key = (f.rule_id, str(f.affected_object).strip().lower())
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                # Merge evidence IDs into existing matching finding
                for existing in unique:
                    if (existing.rule_id, str(existing.affected_object).strip().lower()) == key:
                        for eid in f.evidence_ids:
                            if eid not in existing.evidence_ids:
                                existing.evidence_ids.append(eid)
                        break

        return unique
