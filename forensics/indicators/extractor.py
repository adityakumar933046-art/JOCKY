"""
JOCKY Forensic Indicator Extractor.
Extracts, validates, deduplicates, and scores forensic indicators (IOCs)
from normalized artifacts across heterogeneous systems.
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Dict, List, Optional, Tuple, Set
import uuid

from forensics.indicators.models import Indicator, IndicatorType
from forensics.normalization.models import NormalizedArtifact, NormalizedArtifactType

IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?!(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}\b")
SHA256_PATTERN = re.compile(r"\b[A-Fa-f0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32}\b")
SUSPICIOUS_PATHS = [
    "/tmp", "/dev/shm", "/var/tmp",
    "\\temp\\", "\\appdata\\local\\temp\\", "c:\\temp",
]


class IndicatorExtractor:
    """Extracts, classifies, and indexes forensic indicators from normalized artifacts."""

    def extract_from_artifacts(
        self,
        artifacts: List[NormalizedArtifact],
        organization_id: str = "org-default",
    ) -> List[Indicator]:
        """Extract and index deduplicated indicators from a collection of normalized artifacts."""
        extracted: Dict[Tuple[str, str], Indicator] = {}

        for art in artifacts:
            iocs = self._extract_artifact_indicators(art)
            for itype, ivalue, isev, imeta in iocs:
                key = (itype.value, ivalue)
                now_str = datetime.now(timezone.utc).isoformat()
                if key not in extracted:
                    extracted[key] = Indicator(
                        indicator_id=f"IOC-{uuid.uuid4().hex[:8].upper()}",
                        organization_id=organization_id,
                        indicator_type=itype.value,
                        value=ivalue,
                        first_seen=art.timestamp or now_str,
                        last_seen=art.timestamp or now_str,
                        occurrences=1,
                        severity=isev,
                        source_artifacts=[art.artifact_id],
                        agents_observed=[art.agent_id] if art.agent_id else [],
                        metadata=imeta,
                    )
                else:
                    ind = extracted[key]
                    ind.occurrences += 1
                    ind.last_seen = art.timestamp or now_str
                    if art.artifact_id not in ind.source_artifacts:
                        ind.source_artifacts.append(art.artifact_id)
                    if art.agent_id and art.agent_id not in ind.agents_observed:
                        ind.agents_observed.append(art.agent_id)
                    # Elevate severity if higher
                    if self._severity_rank(isev) > self._severity_rank(ind.severity):
                        ind.severity = isev

        return list(extracted.values())

    def _extract_artifact_indicators(
        self,
        art: NormalizedArtifact,
    ) -> List[Tuple[IndicatorType, str, str, Dict]]:
        """Extract typed indicators from an individual artifact."""
        results: List[Tuple[IndicatorType, str, str, Dict]] = []
        attrs = art.normalized_attributes or {}

        # 1. PROCESS Artifacts
        if art.artifact_type == NormalizedArtifactType.PROCESS.value:
            pname = attrs.get("name")
            if pname:
                results.append((IndicatorType.PROCESS_NAME, pname, "INFO", {"pid": attrs.get("pid")}))
            ppath = attrs.get("path")
            if ppath and ppath not in ("[System Process]", "System"):
                sev = "HIGH" if self._is_suspicious_path(ppath) else "INFO"
                results.append((IndicatorType.FILE_PATH, ppath, sev, {"process": pname}))
            sha256 = attrs.get("sha256")
            if sha256 and len(sha256) == 64:
                results.append((IndicatorType.SHA256, sha256.lower(), "MEDIUM", {"source": "process"}))
            md5 = attrs.get("md5")
            if md5 and len(md5) == 32:
                results.append((IndicatorType.MD5, md5.lower(), "MEDIUM", {"source": "process"}))

        # 2. NETWORK Artifacts
        elif art.artifact_type == NormalizedArtifactType.NETWORK.value:
            rip = attrs.get("remote_ip")
            rport = attrs.get("remote_port", 0)
            if rip and self._is_valid_public_ip(rip):
                # Public IP connection
                sev = "HIGH" if rport in [4444, 1337, 8888, 9001, 6667] else "MEDIUM"
                results.append((IndicatorType.IPV4, rip, sev, {
                    "remote_port": rport,
                    "protocol": attrs.get("protocol"),
                    "process": attrs.get("process_name"),
                }))
            if rport and rport > 0:
                results.append((IndicatorType.PORT, str(rport), "INFO", {
                    "protocol": attrs.get("protocol"),
                    "direction": "remote" if rip else "local",
                }))

        # 3. FILE Artifacts
        elif art.artifact_type == NormalizedArtifactType.FILE.value:
            fpath = attrs.get("path")
            if fpath:
                sev = "HIGH" if self._is_suspicious_path(fpath) else "INFO"
                results.append((IndicatorType.FILE_PATH, fpath, sev, {"filename": attrs.get("filename")}))
            sha256 = attrs.get("sha256")
            if sha256 and len(sha256) == 64:
                results.append((IndicatorType.SHA256, sha256.lower(), "MEDIUM", {"path": fpath}))
            md5 = attrs.get("md5")
            if md5 and len(md5) == 32:
                results.append((IndicatorType.MD5, md5.lower(), "MEDIUM", {"path": fpath}))

        # 4. SERVICE Artifacts
        elif art.artifact_type == NormalizedArtifactType.SERVICE.value:
            sname = attrs.get("service_name")
            if sname:
                results.append((IndicatorType.SERVICE_NAME, sname, "INFO", {"display_name": attrs.get("display_name")}))
            binpath = attrs.get("binpath")
            if binpath:
                sev = "HIGH" if self._is_suspicious_path(binpath) else "INFO"
                results.append((IndicatorType.FILE_PATH, binpath, sev, {"service": sname}))

        # 5. DRIVER Artifacts
        elif art.artifact_type == NormalizedArtifactType.DRIVER.value:
            dname = attrs.get("driver_name")
            if dname:
                is_signed = attrs.get("signed", True)
                sev = "HIGH" if not is_signed else "INFO"
                results.append((IndicatorType.DRIVER_NAME, dname, sev, {"signed": is_signed}))
            dpath = attrs.get("path")
            if dpath:
                results.append((IndicatorType.FILE_PATH, dpath, "INFO", {"driver": dname}))

        # 6. PERSISTENCE Artifacts
        elif art.artifact_type == NormalizedArtifactType.PERSISTENCE.value:
            loc = attrs.get("location")
            if loc and ("CurrentVersion\\Run" in loc or "RunOnce" in loc):
                results.append((IndicatorType.REGISTRY_KEY, loc, "MEDIUM", {"name": attrs.get("name")}))
            cmd = attrs.get("command") or attrs.get("target_path")
            if cmd:
                sev = "HIGH" if self._is_suspicious_path(cmd) else "MEDIUM"
                results.append((IndicatorType.FILE_PATH, cmd, sev, {"entry_type": attrs.get("entry_type")}))

        # Fallback regex scan on raw data string
        raw_str = str(art.raw_data)
        for ip in IPV4_PATTERN.findall(raw_str):
            if self._is_valid_public_ip(ip):
                results.append((IndicatorType.IPV4, ip, "INFO", {"context": "raw_evidence"}))

        return results

    def _is_valid_public_ip(self, ip_str: str) -> bool:
        """Validate if an IPv4 is routable and not loopback/multicast/broadcast."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.version == 4 and not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip_str == "255.255.255.255")
        except ValueError:
            return False

    def _is_suspicious_path(self, path: str) -> bool:
        """Check if path is located in suspicious, world-writable or transient forensic locations."""
        p_lower = path.lower().replace("/", "\\")
        for susp in SUSPICIOUS_PATHS:
            if susp.lower() in p_lower:
                return True
        return False

    def _severity_rank(self, sev: str) -> int:
        ranks = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return ranks.get(sev.upper(), 1)


default_indicator_extractor = IndicatorExtractor()
