"""
JOCKY Forensic Normalization Engine.
Transforms heterogeneous raw evidence records from Windows and Linux endpoints
into canonical, standardized NormalizedArtifact models with uniform schemas.
"""

from datetime import datetime, timezone
import hashlib
import os
from typing import Any, Dict, List, Optional, Union
import uuid

from forensics.normalization.models import (
    NormalizedArtifact,
    NormalizedArtifactType,
)
from forensics.normalization.registry import default_normalization_registry, NormalizationRegistry


class NormalizationEngine:
    def __init__(self, registry: Optional[NormalizationRegistry] = None):
        self.registry = registry or default_normalization_registry

    def normalize_evidence(
        self,
        evidence_id: str,
        operation: str,
        data: Any,
        hostname: str = "",
        agent_id: str = "",
        job_id: Optional[str] = None,
        organization_id: str = "org-default",
        timestamp: Optional[str] = None,
    ) -> List[NormalizedArtifact]:
        """
        Normalize a raw evidence record or payload into canonical NormalizedArtifact models.
        """
        artifact_type = self.registry.resolve_type(operation)
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        # Extract items from payload
        items = self._extract_items(data)
        artifacts: List[NormalizedArtifact] = []

        if not items:
            return artifacts

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                item = {"value": item}

            item_type = self._infer_item_type(item, artifact_type)
            norm_attrs, indicators = self._normalize_item(item_type, item, hostname)
            
            # Deterministic/stable artifact ID based on evidence, type, and index
            seed = f"{evidence_id}:{item_type.value}:{idx}"
            art_id = f"ART-{hashlib.sha256(seed.encode()).hexdigest()[:10].upper()}"

            artifact = NormalizedArtifact(
                artifact_id=art_id,
                organization_id=organization_id,
                agent_id=agent_id,
                evidence_id=evidence_id,
                job_id=job_id,
                hostname=hostname,
                artifact_type=item_type.value,
                timestamp=ts,
                normalized_attributes=norm_attrs,
                raw_data=item,
                indicators=indicators,
            )
            artifacts.append(artifact)

        return artifacts

    def _extract_items(self, data: Any) -> List[Dict[str, Any]]:
        """Safely extract list of items from diverse collector result structures."""
        if not data:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Check for standard keys
            for key in ["items", "processes", "connections", "files", "services", "drivers", "entries"]:
                if key in data and isinstance(data[key], list):
                    return data[key]
            # System info or single dictionary
            return [data]
    def _infer_item_type(self, item: Dict[str, Any], default_type: NormalizedArtifactType) -> NormalizedArtifactType:
        """Infer specialized artifact type if item attributes clearly indicate a different category."""
        if "remote_ip" in item or "remote_address" in item or ("local_ip" in item and "remote_port" in item):
            return NormalizedArtifactType.NETWORK
        if "entry_type" in item or ("location" in item and ("Run" in str(item.get("location")) or "cron" in str(item.get("location")))):
            return NormalizedArtifactType.PERSISTENCE
        if "service_name" in item or "binpath" in item:
            return NormalizedArtifactType.SERVICE
        if "driver_name" in item or ("signed" in item and "pid" not in item):
            return NormalizedArtifactType.DRIVER
        if ("filename" in item or "size_bytes" in item or "size" in item) and "pid" not in item:
            return NormalizedArtifactType.FILE
        if "pid" in item and ("ppid" in item or "cmdline" in item or "exe_path" in item):
            return NormalizedArtifactType.PROCESS
        return default_type

    def _normalize_item(
        self,
        artifact_type: NormalizedArtifactType,
        item: Dict[str, Any],
        hostname: str,
    ) -> tuple[Dict[str, Any], List[str]]:
        """Normalize a single item based on its artifact type."""
        indicators: List[str] = []
        norm: Dict[str, Any] = {}

        if artifact_type == NormalizedArtifactType.PROCESS:
            pid = item.get("pid") or item.get("th32ProcessID") or item.get("ProcessId")
            ppid = item.get("ppid") or item.get("th32ParentProcessID") or item.get("ParentProcessId")
            name = item.get("name") or item.get("szExeFile") or item.get("ProcessName") or ""
            path = item.get("exe_path") or item.get("path") or item.get("ExecutablePath") or ""
            cmdline = item.get("cmdline") or item.get("command_line") or item.get("CommandLine") or ""
            if isinstance(cmdline, list):
                cmdline = " ".join(cmdline)

            hashes = item.get("hashes", {})
            sha256 = hashes.get("sha256") or item.get("sha256") or ""
            md5 = hashes.get("md5") or item.get("md5") or ""

            norm = {
                "pid": int(pid) if pid is not None and str(pid).isdigit() else 0,
                "ppid": int(ppid) if ppid is not None and str(ppid).isdigit() else 0,
                "name": str(name).strip(),
                "path": str(path).strip(),
                "cmdline": str(cmdline).strip(),
                "user": str(item.get("user") or item.get("username") or "").strip(),
                "sha256": str(sha256).strip().lower(),
                "md5": str(md5).strip().lower(),
            }
            if norm["name"]:
                indicators.append(norm["name"])
            if norm["path"]:
                indicators.append(norm["path"])
            if norm["sha256"]:
                indicators.append(norm["sha256"])
            if norm["md5"]:
                indicators.append(norm["md5"])

        elif artifact_type == NormalizedArtifactType.NETWORK:
            lip = item.get("local_ip") or item.get("local_address") or "0.0.0.0"
            lport = item.get("local_port") or 0
            rip = item.get("remote_ip") or item.get("remote_address") or ""
            rport = item.get("remote_port") or 0
            proto = (item.get("protocol") or item.get("proto") or "TCP").upper()
            state = (item.get("state") or item.get("status") or "UNKNOWN").upper()
            pid = item.get("pid") or 0
            pname = item.get("process_name") or item.get("name") or ""

            norm = {
                "local_ip": str(lip).strip(),
                "local_port": int(lport) if str(lport).isdigit() else 0,
                "remote_ip": str(rip).strip(),
                "remote_port": int(rport) if str(rport).isdigit() else 0,
                "protocol": str(proto).strip(),
                "state": str(state).strip(),
                "pid": int(pid) if str(pid).isdigit() else 0,
                "process_name": str(pname).strip(),
            }
            if norm["remote_ip"] and norm["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::1", ""):
                indicators.append(norm["remote_ip"])
            if norm["remote_port"]:
                indicators.append(f"{norm['remote_port']}/{norm['protocol']}")

        elif artifact_type == NormalizedArtifactType.FILE:
            fpath = item.get("path") or item.get("filepath") or item.get("target_path") or ""
            size = item.get("size") or item.get("size_bytes") or item.get("file_size") or 0
            hashes = item.get("hashes", {})
            sha256 = hashes.get("sha256") or item.get("sha256") or ""
            md5 = hashes.get("md5") or item.get("md5") or ""

            norm = {
                "path": str(fpath).strip(),
                "filename": os.path.basename(str(fpath).replace("\\", "/")),
                "size_bytes": int(size) if str(size).isdigit() else 0,
                "sha256": str(sha256).strip().lower(),
                "md5": str(md5).strip().lower(),
                "created_at": item.get("created") or item.get("created_at") or "",
                "modified_at": item.get("modified") or item.get("modified_at") or "",
            }
            if norm["path"]:
                indicators.append(norm["path"])
            if norm["sha256"]:
                indicators.append(norm["sha256"])
            if norm["md5"]:
                indicators.append(norm["md5"])

        elif artifact_type == NormalizedArtifactType.SERVICE:
            sname = item.get("name") or item.get("service_name") or ""
            dname = item.get("display_name") or sname
            status = item.get("status") or item.get("state") or "UNKNOWN"
            binpath = item.get("binpath") or item.get("binary_path") or item.get("path") or ""
            pid = item.get("pid") or 0

            norm = {
                "service_name": str(sname).strip(),
                "display_name": str(dname).strip(),
                "status": str(status).strip().upper(),
                "start_type": str(item.get("start_type") or "").strip(),
                "binpath": str(binpath).strip(),
                "pid": int(pid) if str(pid).isdigit() else 0,
            }
            if norm["service_name"]:
                indicators.append(norm["service_name"])
            if norm["binpath"]:
                indicators.append(norm["binpath"])

        elif artifact_type == NormalizedArtifactType.DRIVER:
            dname = item.get("name") or item.get("driver_name") or ""
            dpath = item.get("path") or ""
            signed = item.get("signed")

            norm = {
                "driver_name": str(dname).strip(),
                "display_name": str(item.get("display_name") or dname).strip(),
                "path": str(dpath).strip(),
                "status": str(item.get("status") or "LOADED").strip(),
                "signed": bool(signed) if signed is not None else False,
            }
            if norm["driver_name"]:
                indicators.append(norm["driver_name"])
            if norm["path"]:
                indicators.append(norm["path"])

        elif artifact_type == NormalizedArtifactType.PERSISTENCE:
            etype = item.get("type") or item.get("entry_type") or "Registry"
            name = item.get("name") or item.get("key") or ""
            loc = item.get("location") or item.get("path") or ""
            target = item.get("target_path") or item.get("target") or item.get("value") or ""
            cmd = item.get("command") or item.get("cmd") or target

            norm = {
                "entry_type": str(etype).strip(),
                "name": str(name).strip(),
                "location": str(loc).strip(),
                "target_path": str(target).strip(),
                "command": str(cmd).strip(),
                "enabled": bool(item.get("enabled", True)),
            }
            if norm["target_path"]:
                indicators.append(norm["target_path"])
            if norm["name"]:
                indicators.append(norm["name"])

        elif artifact_type == NormalizedArtifactType.SYSTEM:
            norm = {
                "hostname": str(item.get("hostname") or hostname).strip(),
                "os": str(item.get("os") or item.get("operating_system") or "").strip(),
                "version": str(item.get("version") or item.get("os_version") or "").strip(),
                "architecture": str(item.get("architecture") or item.get("arch") or "").strip(),
                "boot_time": str(item.get("boot_time") or "").strip(),
                "username": str(item.get("username") or item.get("user") or "").strip(),
            }
            if norm["hostname"]:
                indicators.append(norm["hostname"])

        elif artifact_type == NormalizedArtifactType.USER:
            uname = item.get("username") or item.get("name") or item.get("user") or ""
            norm = {
                "username": str(uname).strip(),
                "uid": str(item.get("uid") or "").strip(),
                "groups": item.get("groups", []),
                "home": str(item.get("home") or "").strip(),
            }
            if norm["username"]:
                indicators.append(norm["username"])

        else:  # EVENT or fallback
            norm = {
                "event_id": str(item.get("event_id") or item.get("id") or "").strip(),
                "source": str(item.get("source") or item.get("provider") or "").strip(),
                "message": str(item.get("message") or item.get("text") or str(item)).strip(),
            }

        return norm, list(dict.fromkeys(indicators))  # Deduplicated indicators
