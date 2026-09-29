"""
JOCKY Linux Forensic Collector.

Performs safe, strictly read-only forensic data collection on Linux hosts (Ubuntu, Debian, RHEL, etc.).
Uses native Linux interfaces (/proc, /etc, systemd) and handles permission errors gracefully.
"""

import os
import sys
import time
import socket
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from runtime.collectors.base import ForensicCollector


class LinuxCollector(ForensicCollector):
    def __init__(self, proc_root: str = "/proc", etc_root: str = "/etc"):
        super().__init__(platform_name="Linux")
        self.proc_root = Path(proc_root)
        self.etc_root = Path(etc_root)

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect host system metadata on Linux."""
        distro = "Linux"
        os_release = self.etc_root / "os-release"
        if os_release.exists():
            try:
                for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=", 1)[1].strip('"\'')
                        break
            except Exception:
                pass

        boot_time_iso = None
        uptime_file = self.proc_root / "uptime"
        if uptime_file.exists():
            try:
                uptime_sec = float(uptime_file.read_text().split()[0])
                boot_epoch = time.time() - uptime_sec
                boot_time_iso = datetime.fromtimestamp(boot_epoch, timezone.utc).isoformat()
            except Exception:
                pass

        username = os.environ.get("USER") or os.environ.get("LOGNAME")
        if not username:
            try:
                username = os.getlogin()
            except Exception:
                username = "UNKNOWN"

        info = {
            "hostname": platform.node() or socket.gethostname(),
            "os": "Linux",
            "kernel": platform.release(),
            "distribution": distro,
            "architecture": platform.machine(),
            "username": username,
            "python_version": sys.version.split()[0],
            "boot_time": boot_time_iso,
        }
        return self._create_result(operation="system_info", items=info)

    def scan_processes(self) -> Dict[str, Any]:
        """Collect running process metadata on Linux via /proc or ps."""
        processes = []

        if self.proc_root.exists() and self.proc_root.is_dir():
            for entry in self.proc_root.iterdir():
                if entry.name.isdigit():
                    pid = int(entry.name)
                    proc_info = {
                        "pid": pid,
                        "name": None,
                        "executable": None,
                        "parent_pid": None,
                        "user": None,
                        "start_time": None,
                        "error": None,
                    }

                    # Read comm (process name)
                    comm_file = entry / "comm"
                    if comm_file.exists():
                        try:
                            proc_info["name"] = comm_file.read_text(encoding="utf-8", errors="ignore").strip()
                        except (PermissionError, FileNotFoundError):
                            pass

                    # Read exe symlink (handled with permission check)
                    exe_symlink = entry / "exe"
                    try:
                        proc_info["executable"] = os.readlink(exe_symlink)
                    except PermissionError:
                        proc_info["error"] = "ACCESS_DENIED"
                    except (FileNotFoundError, OSError):
                        pass

                    # Read stat for parent PID
                    stat_file = entry / "stat"
                    if stat_file.exists():
                        try:
                            parts = stat_file.read_text().split()
                            if len(parts) > 3:
                                proc_info["parent_pid"] = int(parts[3])
                        except Exception:
                            pass

                    # Read status for UID
                    status_file = entry / "status"
                    if status_file.exists():
                        try:
                            for sline in status_file.read_text().splitlines():
                                if sline.startswith("Uid:"):
                                    proc_info["user"] = sline.split()[1]
                                    break
                        except Exception:
                            pass

                    processes.append(proc_info)

        # Fallback to ps if /proc yielded nothing (e.g. cross-testing on non-Linux host)
        if not processes:
            try:
                res = subprocess.run(
                    ["ps", "-eo", "pid,ppid,user,comm"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                for line in res.stdout.splitlines()[1:]:
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 4:
                        try:
                            processes.append({
                                "pid": int(parts[0]),
                                "parent_pid": int(parts[1]),
                                "user": parts[2],
                                "name": parts[3],
                                "executable": None,
                            })
                        except ValueError:
                            continue
            except Exception:
                pass

        return self._create_result(operation="processes", items=processes)

    def scan_network(self) -> Dict[str, Any]:
        """Collect active network connections on Linux via /proc/net or ss."""
        connections = []

        # Read /proc/net/tcp
        tcp_file = self.proc_root / "net" / "tcp"
        if tcp_file.exists():
            try:
                for line in tcp_file.read_text().splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        local_hex, local_port_hex = parts[1].split(":")
                        remote_hex, remote_port_hex = parts[2].split(":")
                        st_hex = parts[3]

                        state_map = {
                            "01": "ESTABLISHED",
                            "02": "SYN_SENT",
                            "03": "SYN_RECV",
                            "0A": "LISTENING",
                        }

                        connections.append({
                            "protocol": "TCP",
                            "local_address": self._hex_to_ip(local_hex),
                            "local_port": int(local_port_hex, 16),
                            "remote_address": self._hex_to_ip(remote_hex),
                            "remote_port": int(remote_port_hex, 16),
                            "state": state_map.get(st_hex, f"STATE_{st_hex}"),
                            "pid": None,
                        })
            except Exception:
                pass

        # Fallback to ss command if /proc/net/tcp not present or empty
        if not connections:
            try:
                res = subprocess.run(
                    ["ss", "-tulpan"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                for line in res.stdout.splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        connections.append({
                            "protocol": parts[0].upper(),
                            "state": parts[1],
                            "local_address": parts[4],
                            "remote_address": parts[5] if len(parts) > 5 else "*",
                            "pid": None,
                        })
            except Exception:
                pass

        return self._create_result(operation="network", items=connections)

    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        """Convert little-endian hex string to dotted IPv4."""
        try:
            octets = [int(hex_str[i:i+2], 16) for i in (6, 4, 2, 0)]
            return ".".join(map(str, octets))
        except Exception:
            return hex_str

    def scan_drivers(self) -> Dict[str, Any]:
        """Collect loaded kernel modules from /proc/modules or lsmod."""
        modules = []
        modules_file = self.proc_root / "modules"
        if modules_file.exists():
            try:
                for line in modules_file.read_text().splitlines():
                    parts = line.strip().split()
                    if parts:
                        modules.append({
                            "module_name": parts[0],
                            "size": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else parts[1],
                            "instances": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                            "state": parts[4] if len(parts) > 4 else "Live",
                        })
            except Exception as e:
                return self._create_result(
                    operation="drivers",
                    items=[],
                    status="error",
                    error=f"Failed reading /proc/modules: {e}",
                )
        else:
            # Fallback to lsmod
            try:
                res = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5, check=False)
                for line in res.stdout.splitlines()[1:]:
                    parts = line.strip().split()
                    if parts:
                        modules.append({
                            "module_name": parts[0],
                            "size": parts[1] if len(parts) > 1 else None,
                            "used_by": parts[3] if len(parts) > 3 else None,
                            "state": "Loaded",
                        })
            except Exception:
                pass

        return self._create_result(operation="drivers", items=modules)

    def scan_services(self) -> Dict[str, Any]:
        """Collect systemd service units safely without modifying service state."""
        services = []
        try:
            res = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split(None, 4)
                if len(parts) >= 4:
                    services.append({
                        "service_name": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4] if len(parts) > 4 else "",
                    })
        except Exception:
            # Fallback: inspect /etc/systemd/system or /etc/init.d
            systemd_dir = self.etc_root / "systemd" / "system"
            if systemd_dir.exists():
                try:
                    for f in systemd_dir.glob("*.service"):
                        services.append({
                            "service_name": f.name,
                            "load": "Configured",
                            "active": "Unknown",
                            "path": str(f),
                        })
                except Exception:
                    pass

        return self._create_result(operation="services", items=services)

    def scan_files(self, paths: Optional[List[str]] = None, calculate_hashes: bool = False) -> Dict[str, Any]:
        """Collect controlled Linux file metadata without full disk traversal."""
        if paths is None:
            paths = ["/etc/passwd", "/etc/hosts", "/etc/resolv.conf"]

        results = []
        for p in paths:
            fpath = Path(p)
            entry = {
                "path": str(fpath),
                "filename": fpath.name,
                "exists": fpath.exists(),
                "size": None,
                "created_time": None,
                "modified_time": None,
                "accessed_time": None,
                "extension": fpath.suffix.lower(),
                "sha256": None,
                "error": None,
            }

            if not fpath.exists():
                entry["error"] = "FILE_NOT_FOUND"
                results.append(entry)
                continue

            try:
                st = fpath.stat()
                entry["size"] = st.st_size
                entry["created_time"] = datetime.fromtimestamp(st.st_ctime, timezone.utc).isoformat()
                entry["modified_time"] = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()
                entry["accessed_time"] = datetime.fromtimestamp(st.st_atime, timezone.utc).isoformat()

                if calculate_hashes and fpath.is_file():
                    hasher = hashlib.sha256()
                    with open(fpath, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            hasher.update(chunk)
                    entry["sha256"] = hasher.hexdigest()

            except PermissionError:
                entry["error"] = "ACCESS_DENIED"
            except Exception as e:
                entry["error"] = str(e)

            results.append(entry)

        return self._create_result(operation="files", items=results)

    def analyze_persistence(self) -> Dict[str, Any]:
        """Read-only inspection of Linux cron jobs, systemd timers, and init scripts."""
        persistence = []

        # Cron directories
        cron_paths = [
            self.etc_root / "crontab",
            self.etc_root / "cron.d",
            self.etc_root / "cron.daily",
            self.etc_root / "cron.hourly",
        ]
        for cpath in cron_paths:
            if cpath.exists():
                if cpath.is_file():
                    persistence.append({
                        "type": "CronFile",
                        "location": str(cpath),
                    })
                elif cpath.is_dir():
                    try:
                        for entry in cpath.iterdir():
                            persistence.append({
                                "type": "CronJob",
                                "location": str(entry),
                                "name": entry.name,
                            })
                    except Exception:
                        pass

        # Bash profile persistence
        home = Path(os.environ.get("HOME", "/root"))
        for rc_file in [home / ".bashrc", home / ".bash_profile", home / ".profile"]:
            if rc_file.exists():
                persistence.append({
                    "type": "ShellProfile",
                    "location": str(rc_file),
                })

        return self._create_result(operation="persistence", items=persistence)

    def analyze_memory(self) -> Dict[str, Any]:
        """Read-only memory utilization metrics from /proc/meminfo."""
        meminfo_data = {}
        mem_file = self.proc_root / "meminfo"
        if mem_file.exists():
            try:
                for line in mem_file.read_text().splitlines():
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip()
                        meminfo_data[key] = val
            except Exception as e:
                meminfo_data["error"] = f"Failed reading meminfo: {e}"

        return self._create_result(operation="memory", items=meminfo_data)

    def analyze_network(self) -> Dict[str, Any]:
        """Read-only network exposure and listening port analysis on Linux."""
        net_scan = self.scan_network()
        connections = net_scan.get("items", [])

        listening = [c for c in connections if c.get("state") == "LISTENING"]
        established = [c for c in connections if c.get("state") == "ESTABLISHED"]

        analysis = {
            "total_active_connections": len(connections),
            "listening_ports_count": len(listening),
            "listening_ports": listening[:50],
            "established_connections": established[:50],
        }
        return self._create_result(operation="network_analysis", items=analysis)
