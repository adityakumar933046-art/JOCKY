"""
JOCKY Forensic Collector Base Interface.

Defines the abstract interface for platform-specific read-only forensic collectors.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ForensicCollector(ABC):
    """Abstract base class for all platform forensic collectors.
    
    All operations are strictly read-only and designed for safe forensic extraction.
    """

    def __init__(self, platform_name: str):
        self.platform_name = platform_name

    def _create_result(
        self,
        operation: str,
        items: Any,
        status: str = "success",
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standardized envelope for forensic collection results."""
        return {
            "collector": self.__class__.__name__,
            "platform": self.platform_name,
            "operation": operation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "items": items,
            "error": error,
            "metadata": metadata or {},
        }

    @abstractmethod
    def collect_system_info(self) -> Dict[str, Any]:
        """Collect host system metadata (OS, version, hostname, arch, boot time)."""
        pass

    @abstractmethod
    def scan_processes(self) -> Dict[str, Any]:
        """Collect running process metadata (PID, name, exe, ppid, user, start time)."""
        pass

    @abstractmethod
    def scan_network(self) -> Dict[str, Any]:
        """Collect active network sockets (protocol, local/remote addr, state, pid)."""
        pass

    @abstractmethod
    def scan_files(self, paths: Optional[List[str]] = None, calculate_hashes: bool = False) -> Dict[str, Any]:
        """Collect controlled file metadata for specified paths (size, timestamps, ext)."""
        pass

    @abstractmethod
    def scan_drivers(self) -> Dict[str, Any]:
        """Collect loaded kernel drivers / modules."""
        pass

    @abstractmethod
    def scan_services(self) -> Dict[str, Any]:
        """Collect registered system services and execution status."""
        pass

    @abstractmethod
    def analyze_persistence(self) -> Dict[str, Any]:
        """Analyze standard autorun / persistence locations in read-only mode."""
        pass

    @abstractmethod
    def analyze_memory(self) -> Dict[str, Any]:
        """Analyze high-level memory statistics and allocation indicators."""
        pass

    @abstractmethod
    def analyze_network(self) -> Dict[str, Any]:
        """Analyze network exposure, listening services, and routing indicators."""
        pass
