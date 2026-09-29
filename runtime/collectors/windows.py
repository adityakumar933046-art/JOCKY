"""
JOCKY Windows Forensic Collector.

Performs safe, strictly read-only forensic data collection on Windows hosts.
Gracefully handles access-denied errors, missing metadata, and transient processes.
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


class WindowsCollector(ForensicCollector):
    def __init__(self):
        super().__init__(platform_name="Windows")

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect host system metadata on Windows."""
        boot_time_iso = None
        try:
            import ctypes
            uptime_ms = ctypes.windll.kernel32.GetTickCount64()
            boot_epoch = time.time() - (uptime_ms / 1000.0)
            boot_time_iso = datetime.fromtimestamp(boot_epoch, timezone.utc).isoformat()
        except Exception:
            pass

        username = os.environ.get("USERNAME") or os.environ.get("USER")
        if not username:
            try:
                username = os.getlogin()
            except Exception:
                username = "UNKNOWN"

        info = {
            "hostname": platform.node() or socket.gethostname(),
            "os": "Windows",
            "version": platform.version(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "username": username,
            "python_version": sys.version.split()[0],
            "boot_time": boot_time_iso,
        }
        return self._create_result(operation="system_info", items=info)

    def scan_processes(self) -> Dict[str, Any]:
        """Collect running process metadata on Windows without elevated injection or termination."""
        processes = []
        try:
            import ctypes
            from ctypes import wintypes

            TH32CS_SNAPPROCESS = 0x00000002
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260),
                ]

            snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snap and snap != -1:
                pe = PROCESSENTRY32W()
                pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

                success = ctypes.windll.kernel32.Process32FirstW(snap, ctypes.byref(pe))
                while success:
                    pid = pe.th32ProcessID
                    ppid = pe.th32ParentProcessID
                    name = pe.szExeFile
                    exe_path = None
                    err_msg = None

                    if pid == 0:
                        exe_path = "[System Process]"
                    elif pid == 4:
                        exe_path = "System"
                        err_msg = "ACCESS_DENIED"
                    else:
                        h_proc = ctypes.windll.kernel32.OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
                        )
                        if h_proc:
                            buf = ctypes.create_unicode_buffer(1024)
                            size = wintypes.DWORD(1024)
                            if ctypes.windll.kernel32.QueryFullProcessImageNameW(
                                h_proc, 0, buf, ctypes.byref(size)
                            ):
                                exe_path = buf.value
                            else:
                                err_msg = "IMAGE_QUERY_FAILED"
                            ctypes.windll.kernel32.CloseHandle(h_proc)
                        else:
                            last_err = ctypes.GetLastError()
                            err_msg = "ACCESS_DENIED" if last_err == 5 else f"ERROR_{last_err}"

                    proc_entry = {
                        "pid": pid,
                        "name": name,
                        "executable": exe_path,
                        "parent_pid": ppid,
                        "username": None,
                        "creation_time": None,
                    }
                    if err_msg:
                        proc_entry["error"] = err_msg

                    processes.append(proc_entry)
                    success = ctypes.windll.kernel32.Process32NextW(snap, ctypes.byref(pe))

                ctypes.windll.kernel32.CloseHandle(snap)

        except Exception as e:
            # Fallback to tasklist /FO CSV if ctypes snapshot is unavailable
            try:
                res = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                import csv
                import io
                reader = csv.reader(io.StringIO(res.stdout))
                for row in reader:
                    if len(row) >= 2:
                        try:
                            processes.append({
                                "pid": int(row[1]),
                                "name": row[0],
                                "executable": None,
                                "parent_pid": None,
                                "username": row[6] if len(row) > 6 else None,
                                "creation_time": None,
                            })
                        except ValueError:
                            continue
            except Exception as sub_e:
                return self._create_result(
                    operation="processes",
                    items=[],
                    status="error",
                    error=f"Process collection failed: {e}; Fallback: {sub_e}",
                )

        return self._create_result(operation="processes", items=processes)

    def scan_network(self) -> Dict[str, Any]:
        """Collect active network sockets on Windows using netstat."""
        connections = []
        try:
            res = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if not parts or parts[0].upper() not in ("TCP", "UDP"):
                    continue

                proto = parts[0].upper()
                local_addr_str = parts[1] if len(parts) > 1 else ""
                remote_addr_str = parts[2] if len(parts) > 2 else ""

                state = None
                pid = None

                if proto == "TCP":
                    state = parts[3] if len(parts) > 3 else "UNKNOWN"
                    pid_str = parts[4] if len(parts) > 4 else None
                else:
                    state = "N/A"
                    pid_str = parts[3] if len(parts) > 3 else None

                try:
                    pid = int(pid_str) if pid_str else None
                except ValueError:
                    pid = None

                # Parse IP and Port
                local_ip, _, local_port = local_addr_str.rpartition(":")
                remote_ip, _, remote_port = remote_addr_str.rpartition(":")

                connections.append({
                    "protocol": proto,
                    "local_address": local_ip or local_addr_str,
                    "local_port": int(local_port) if local_port.isdigit() else local_port,
                    "remote_address": remote_ip or remote_addr_str,
                    "remote_port": int(remote_port) if remote_port.isdigit() else remote_port,
                    "state": state,
                    "pid": pid,
                })
        except Exception as e:
            return self._create_result(
                operation="network",
                items=[],
                status="error",
                error=f"Network scan error: {e}",
            )

        return self._create_result(operation="network", items=connections)

    def scan_drivers(self) -> Dict[str, Any]:
        """Collect loaded kernel driver entries via safe registry enumeration."""
        drivers = []
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
            )
            num_subkeys = winreg.QueryInfoKey(key)[0]

            for i in range(num_subkeys):
                try:
                    sub_name = winreg.EnumKey(key, i)
                    sub_key = winreg.OpenKey(key, sub_name)

                    try:
                        driver_type, _ = winreg.QueryValueEx(sub_key, "Type")
                    except FileNotFoundError:
                        driver_type = 0

                    # 1 = Kernel Driver, 2 = File System Driver
                    if driver_type in (1, 2):
                        try:
                            display_name, _ = winreg.QueryValueEx(sub_key, "DisplayName")
                        except FileNotFoundError:
                            display_name = sub_name

                        try:
                            image_path, _ = winreg.QueryValueEx(sub_key, "ImagePath")
                        except FileNotFoundError:
                            image_path = None

                        try:
                            start_mode, _ = winreg.QueryValueEx(sub_key, "Start")
                            start_str = {
                                0: "BOOT",
                                1: "SYSTEM",
                                2: "AUTO",
                                3: "MANUAL",
                                4: "DISABLED",
                            }.get(start_mode, f"UNKNOWN({start_mode})")
                        except FileNotFoundError:
                            start_str = "UNKNOWN"

                        drivers.append({
                            "name": sub_name,
                            "display_name": display_name,
                            "path": image_path,
                            "type": "Kernel Driver" if driver_type == 1 else "File System Driver",
                            "start_mode": start_str,
                            "state": "Registered",
                        })
                except Exception:
                    continue

        except Exception as e:
            return self._create_result(
                operation="drivers",
                items=[],
                status="error",
                error=f"Driver collection error: {e}",
            )

        return self._create_result(operation="drivers", items=drivers)

    def scan_services(self) -> Dict[str, Any]:
        """Collect registered Windows services via safe registry inspection."""
        services = []
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
            )
            num_subkeys = winreg.QueryInfoKey(key)[0]

            for i in range(num_subkeys):
                try:
                    sub_name = winreg.EnumKey(key, i)
                    sub_key = winreg.OpenKey(key, sub_name)

                    try:
                        service_type, _ = winreg.QueryValueEx(sub_key, "Type")
                    except FileNotFoundError:
                        service_type = 0

                    # Standard Win32 Services: 16 (Own Process), 32 (Shared Process), 272, etc.
                    if service_type in (16, 32, 272):
                        try:
                            display_name, _ = winreg.QueryValueEx(sub_key, "DisplayName")
                        except FileNotFoundError:
                            display_name = sub_name

                        try:
                            image_path, _ = winreg.QueryValueEx(sub_key, "ImagePath")
                        except FileNotFoundError:
                            image_path = None

                        try:
                            start_mode, _ = winreg.QueryValueEx(sub_key, "Start")
                            start_str = {
                                0: "BOOT",
                                1: "SYSTEM",
                                2: "AUTO",
                                3: "MANUAL",
                                4: "DISABLED",
                            }.get(start_mode, f"UNKNOWN({start_mode})")
                        except FileNotFoundError:
                            start_str = "UNKNOWN"

                        services.append({
                            "service_name": sub_name,
                            "display_name": display_name,
                            "path": image_path,
                            "start_type": start_str,
                            "status": "Configured",
                        })
                except Exception:
                    continue

        except Exception as e:
            return self._create_result(
                operation="services",
                items=[],
                status="error",
                error=f"Service collection error: {e}",
            )

        return self._create_result(operation="services", items=services)

    def scan_files(self, paths: Optional[List[str]] = None, calculate_hashes: bool = False) -> Dict[str, Any]:
        """Collect controlled file metadata without recursive disk traversal."""
        if paths is None:
            # Safe default forensic targets
            windir = os.environ.get("WINDIR", "C:\\Windows")
            paths = [
                os.path.join(windir, "System32", "cmd.exe"),
                os.path.join(windir, "System32", "drivers", "etc", "hosts"),
                os.path.join(windir, "System32", "notepad.exe"),
            ]

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
        """Safe read-only inspection of standard Windows persistence mechanisms."""
        persistence_items = []
        try:
            import winreg
            run_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
            ]

            for root_key, subkey_path, loc_name in run_locations:
                try:
                    k = winreg.OpenKey(root_key, subkey_path)
                    val_count = winreg.QueryInfoKey(k)[1]
                    for i in range(val_count):
                        name, val, val_type = winreg.EnumValue(k, i)
                        persistence_items.append({
                            "type": "RegistryRunKey",
                            "location": loc_name,
                            "entry_name": name,
                            "target_command": str(val),
                        })
                except FileNotFoundError:
                    continue
                except PermissionError:
                    persistence_items.append({
                        "type": "RegistryRunKey",
                        "location": loc_name,
                        "error": "ACCESS_DENIED",
                    })

            # Check User Startup Directory
            appdata = os.environ.get("APPDATA")
            if appdata:
                startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if startup_dir.exists():
                    for item in startup_dir.iterdir():
                        persistence_items.append({
                            "type": "StartupFolder",
                            "location": "UserStartup",
                            "entry_name": item.name,
                            "target_command": str(item),
                        })

        except Exception as e:
            return self._create_result(
                operation="persistence",
                items=[],
                status="error",
                error=f"Persistence analysis error: {e}",
            )

        return self._create_result(operation="persistence", items=persistence_items)

    def analyze_memory(self) -> Dict[str, Any]:
        """Safe read-only memory allocation and utilization indicators."""
        memory_data = {}
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                memory_data = {
                    "memory_load_percent": stat.dwMemoryLoad,
                    "total_physical_bytes": stat.ullTotalPhys,
                    "available_physical_bytes": stat.ullAvailPhys,
                    "total_pagefile_bytes": stat.ullTotalPageFile,
                    "available_pagefile_bytes": stat.ullAvailPageFile,
                    "total_virtual_bytes": stat.ullTotalVirtual,
                    "available_virtual_bytes": stat.ullAvailVirtual,
                }
        except Exception as e:
            memory_data["error"] = f"Memory analysis error: {e}"

        return self._create_result(operation="memory", items=memory_data)

    def analyze_network(self) -> Dict[str, Any]:
        """Safe read-only network indicators: listening ports and external endpoints."""
        net_scan = self.scan_network()
        connections = net_scan.get("items", [])

        listening = []
        established_external = []

        for conn in connections:
            state = conn.get("state")
            if state == "LISTENING":
                listening.append({
                    "port": conn.get("local_port"),
                    "protocol": conn.get("protocol"),
                    "pid": conn.get("pid"),
                })
            elif state == "ESTABLISHED":
                r_addr = conn.get("remote_address", "")
                # Ignore loopback
                if not (r_addr.startswith("127.") or r_addr == "0.0.0.0" or r_addr == "::1"):
                    established_external.append(conn)

        analysis = {
            "total_active_connections": len(connections),
            "listening_ports_count": len(listening),
            "listening_services": listening[:50],  # cap display
            "established_external_connections": established_external[:50],
        }
        return self._create_result(operation="network_analysis", items=analysis)
