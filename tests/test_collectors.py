"""
Unit tests for JOCKY Platform Collectors and Collector Factory.
"""

import sys
import platform
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from runtime.collectors.factory import get_collector, UnsupportedPlatformError
from runtime.collectors.windows import WindowsCollector
from runtime.collectors.linux import LinuxCollector


def test_factory_platform_selection():
    win_col = get_collector("Windows")
    assert isinstance(win_col, WindowsCollector)
    assert win_col.platform_name == "Windows"

    linux_col = get_collector("Linux")
    assert isinstance(linux_col, LinuxCollector)
    assert linux_col.platform_name == "Linux"


def test_factory_unsupported_platform():
    with pytest.raises(UnsupportedPlatformError) as exc_info:
        get_collector("Solaris")
    assert "Unsupported operating system: 'Solaris'" in str(exc_info.value)


def test_windows_collector_system_info():
    collector = WindowsCollector()
    res = collector.collect_system_info()

    assert res["collector"] == "WindowsCollector"
    assert res["operation"] == "system_info"
    assert res["status"] == "success"
    items = res["items"]
    assert items["os"] == "Windows"
    assert "hostname" in items
    assert "architecture" in items
    assert "python_version" in items


def test_windows_collector_process_scan():
    collector = WindowsCollector()
    res = collector.scan_processes()

    assert res["operation"] == "processes"
    assert res["status"] == "success"
    assert isinstance(res["items"], list)
    if res["items"]:
        first = res["items"][0]
        assert "pid" in first
        assert "name" in first


def test_windows_collector_permission_error_handling():
    """Verify that ACCESS_DENIED on a process does not crash the collector."""
    collector = WindowsCollector()
    res = collector.scan_processes()
    items = res["items"]
    # Look for system or access-denied entries
    denied_entries = [p for p in items if p.get("error") == "ACCESS_DENIED"]
    # PID 4 (System) or similar should exist on real Windows and have ACCESS_DENIED
    if platform.system() == "Windows":
        system_pids = [p for p in items if p.get("pid") in (0, 4)]
        assert len(system_pids) > 0


def test_windows_collector_network_scan():
    collector = WindowsCollector()
    res = collector.scan_network()

    assert res["operation"] == "network"
    assert res["status"] in ("success", "partial")
    assert isinstance(res["items"], list)


def test_windows_collector_driver_scan():
    collector = WindowsCollector()
    res = collector.scan_drivers()

    assert res["operation"] == "drivers"
    assert res["status"] in ("success", "partial")
    assert isinstance(res["items"], list)


def test_windows_collector_service_scan():
    collector = WindowsCollector()
    res = collector.scan_services()

    assert res["operation"] == "services"
    assert res["status"] in ("success", "partial")
    assert isinstance(res["items"], list)


def test_windows_collector_file_scan(tmp_path):
    test_file = tmp_path / "forensic_target.txt"
    test_file.write_text("forensic investigation content", encoding="utf-8")

    collector = WindowsCollector()
    res = collector.scan_files(paths=[str(test_file)], calculate_hashes=True)

    assert res["operation"] == "files"
    assert len(res["items"]) == 1
    item = res["items"][0]
    assert item["exists"] is True
    assert item["filename"] == "forensic_target.txt"
    assert item["extension"] == ".txt"
    assert item["sha256"] is not None
    assert len(item["sha256"]) == 64


def test_linux_collector_with_mocked_proc(tmp_path):
    """Test Linux collector parsing on a simulated /proc and /etc filesystem."""
    mock_proc = tmp_path / "proc"
    mock_etc = tmp_path / "etc"
    mock_proc.mkdir()
    mock_etc.mkdir()

    # Mock /etc/os-release
    (mock_etc / "os-release").write_text('PRETTY_NAME="Ubuntu 24.04 LTS"\n', encoding="utf-8")

    # Mock /proc/uptime
    (mock_proc / "uptime").write_text("12345.67 89012.34\n", encoding="utf-8")

    # Mock /proc/1234 (process)
    pdir = mock_proc / "1234"
    pdir.mkdir()
    (pdir / "comm").write_text("bash\n", encoding="utf-8")
    (pdir / "stat").write_text("1234 (bash) S 1 1234 1234 0 -1 4194304 ...\n", encoding="utf-8")

    # Mock /proc/modules
    (mock_proc / "modules").write_text("ext4 819200 1 - Live 0xffffffffc0000000\n", encoding="utf-8")

    collector = LinuxCollector(proc_root=str(mock_proc), etc_root=str(mock_etc))

    # Test system info
    sys_info = collector.collect_system_info()
    assert sys_info["items"]["distribution"] == "Ubuntu 24.04 LTS"
    assert sys_info["items"]["os"] == "Linux"

    # Test processes
    procs = collector.scan_processes()
    assert len(procs["items"]) == 1
    assert procs["items"][0]["pid"] == 1234
    assert procs["items"][0]["name"] == "bash"
    assert procs["items"][0]["parent_pid"] == 1

    # Test drivers / modules
    drivers = collector.scan_drivers()
    assert len(drivers["items"]) == 1
    assert drivers["items"][0]["module_name"] == "ext4"
