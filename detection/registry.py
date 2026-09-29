"""
JOCKY Threat Detection Rule Registry.

Manages registration, retrieval, and categorization of detection rules.
Allows dynamic registration of future custom forensic rules.
"""

from typing import List, Dict, Optional
from detection.rules.base import DetectionRule
from detection.rules.process_rules import (
    SuspiciousProcessRelationshipRule,
    UnusualExecutableLocationRule,
    MissingProcessMetadataRule,
)
from detection.rules.persistence_rules import (
    SuspiciousPersistenceLocationRule,
    ShellProfilePersistenceRule,
)
from detection.rules.driver_rules import (
    DriverPathAnomalyRule,
    PotentiallyVulnerableDriverRule,
)
from detection.rules.network_rules import (
    UnusualListeningPortRule,
    UnexpectedNetworkConnectionRule,
    RepeatedOutboundConnectionRule,
)
from detection.rules.memory_rules import (
    SuspiciousMemoryIndicatorRule,
)
from detection.rules.service_rules import (
    ServiceExecutablePathAnomalyRule,
    SuspiciousServiceConfigurationRule,
)
from detection.rules.file_rules import (
    ExecutableInUnusualLocationRule,
    DeceptiveDoubleExtensionRule,
)


class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule instance."""
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> Optional[DetectionRule]:
        """Remove a rule by its ID."""
        return self._rules.pop(rule_id, None)

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Retrieve a specific rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[DetectionRule]:
        """Return all registered rules in consistent order."""
        return list(self._rules.values())

    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """Return all rules registered under a specific category."""
        cat_upper = category.upper()
        return [r for r in self._rules.values() if r.category.upper() == cat_upper]

    @classmethod
    def create_default(cls) -> "RuleRegistry":
        """Instantiate a registry populated with all standard JOCKY forensic rules."""
        registry = cls()
        # Process Rules
        registry.register(SuspiciousProcessRelationshipRule())
        registry.register(UnusualExecutableLocationRule())
        registry.register(MissingProcessMetadataRule())
        # Persistence Rules
        registry.register(SuspiciousPersistenceLocationRule())
        registry.register(ShellProfilePersistenceRule())
        # Driver Rules
        registry.register(DriverPathAnomalyRule())
        registry.register(PotentiallyVulnerableDriverRule())
        # Network Rules
        registry.register(UnusualListeningPortRule())
        registry.register(UnexpectedNetworkConnectionRule())
        registry.register(RepeatedOutboundConnectionRule())
        # Memory Rules
        registry.register(SuspiciousMemoryIndicatorRule())
        # Service Rules
        registry.register(ServiceExecutablePathAnomalyRule())
        registry.register(SuspiciousServiceConfigurationRule())
        # File Rules
        registry.register(ExecutableInUnusualLocationRule())
        registry.register(DeceptiveDoubleExtensionRule())
        return registry
