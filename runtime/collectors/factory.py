"""
JOCKY Forensic Collector Factory.

Detects host platform and returns the appropriate ForensicCollector implementation.
"""

import platform
from typing import Optional
from runtime.collectors.base import ForensicCollector
from runtime.collectors.windows import WindowsCollector
from runtime.collectors.linux import LinuxCollector


class UnsupportedPlatformError(Exception):
    """Raised when JOCKY is executed on an unsupported operating system."""
    pass


def get_collector(platform_override: Optional[str] = None) -> ForensicCollector:
    """Return a platform-specific ForensicCollector instance.
    
    Args:
        platform_override: Optional platform string ("Windows" or "Linux") for testing.
        
    Raises:
        UnsupportedPlatformError: If platform is not supported.
    """
    system_name = platform_override or platform.system()

    if system_name.lower() == "windows":
        return WindowsCollector()
    elif system_name.lower() == "linux":
        return LinuxCollector()
    else:
        raise UnsupportedPlatformError(
            f"Unsupported operating system: '{system_name}'. "
            f"JOCKY currently supports Windows and Ubuntu/Linux."
        )
