"""
JOCKY Collectors Package.
"""

from runtime.collectors.base import ForensicCollector
from runtime.collectors.windows import WindowsCollector
from runtime.collectors.linux import LinuxCollector
from runtime.collectors.factory import get_collector, UnsupportedPlatformError

__all__ = [
    "ForensicCollector",
    "WindowsCollector",
    "LinuxCollector",
    "get_collector",
    "UnsupportedPlatformError",
]
