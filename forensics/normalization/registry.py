"""
JOCKY Forensic Normalization Registry.
Maps evidence operations and data schemas to appropriate normalization parsers.
"""

from typing import Callable, Dict, Optional
from forensics.normalization.models import NormalizedArtifactType


class NormalizationRegistry:
    def __init__(self):
        self._handlers: Dict[str, Callable] = {}
        self._type_map: Dict[str, NormalizedArtifactType] = {
            "process": NormalizedArtifactType.PROCESS,
            "processes": NormalizedArtifactType.PROCESS,
            "scan_processes": NormalizedArtifactType.PROCESS,
            "collect_processes": NormalizedArtifactType.PROCESS,
            "network": NormalizedArtifactType.NETWORK,
            "scan_network": NormalizedArtifactType.NETWORK,
            "collect_network": NormalizedArtifactType.NETWORK,
            "file": NormalizedArtifactType.FILE,
            "files": NormalizedArtifactType.FILE,
            "scan_files": NormalizedArtifactType.FILE,
            "collect_files": NormalizedArtifactType.FILE,
            "hash_file": NormalizedArtifactType.FILE,
            "service": NormalizedArtifactType.SERVICE,
            "services": NormalizedArtifactType.SERVICE,
            "scan_services": NormalizedArtifactType.SERVICE,
            "collect_services": NormalizedArtifactType.SERVICE,
            "driver": NormalizedArtifactType.DRIVER,
            "drivers": NormalizedArtifactType.DRIVER,
            "scan_drivers": NormalizedArtifactType.DRIVER,
            "collect_drivers": NormalizedArtifactType.DRIVER,
            "persistence": NormalizedArtifactType.PERSISTENCE,
            "scan_persistence": NormalizedArtifactType.PERSISTENCE,
            "collect_persistence": NormalizedArtifactType.PERSISTENCE,
            "system_info": NormalizedArtifactType.SYSTEM,
            "collect_system_info": NormalizedArtifactType.SYSTEM,
            "user": NormalizedArtifactType.USER,
            "users": NormalizedArtifactType.USER,
            "collect_users": NormalizedArtifactType.USER,
            "event": NormalizedArtifactType.EVENT,
            "events": NormalizedArtifactType.EVENT,
            "collect_events": NormalizedArtifactType.EVENT,
        }

    def register(self, operation_pattern: str, handler: Callable):
        self._handlers[operation_pattern.lower()] = handler

    def resolve_type(self, operation: str) -> NormalizedArtifactType:
        op = (operation or "").lower().strip()
        if op in self._type_map:
            return self._type_map[op]
        for key, val in self._type_map.items():
            if key in op:
                return val
        return NormalizedArtifactType.EVENT


default_normalization_registry = NormalizationRegistry()
