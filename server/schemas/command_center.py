"""
JOCKY Forensic Command Center Schemas.
Structured models for multi-system map, adversary matrix, timeline, and correlation telemetry.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class SystemNode(BaseModel):
    agent_id: str
    hostname: str
    operating_system: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    status: str
    trust_state: str
    last_seen: Optional[datetime] = None
    evidence_count: int = 0
    findings_count: int = 0
    max_severity: str = "CLEAN"


class MatrixCategory(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    total: int = 0


class CommandCenterSummary(BaseModel):
    total_systems: int
    online_systems: int
    offline_systems: int
    trusted_systems: int
    total_jobs: int
    active_jobs: int
    total_evidence: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    total_indicators: int
    total_correlations: int
    total_investigations: int
    last_analysis_timestamp: Optional[str] = None


class TimelineEventSummary(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    hostname: str
    summary: str
    severity: str
    category: Optional[str] = None
    details: Dict[str, Any] = {}


class CrossSystemCorrelationSummary(BaseModel):
    correlation_id: str
    indicator_type: str
    indicator_value: str
    agents_count: int
    agent_ids: List[str] = []
    severity: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrences: int = 0


class PriorityInvestigationSummary(BaseModel):
    investigation_id: str
    title: str
    description: Optional[str] = None
    status: str
    assigned_analyst: Optional[str] = None
    created_at: datetime
    systems_count: int = 0
    findings_count: int = 0
    evidence_count: int = 0
    max_severity: str = "INFO"


class EvidenceIntegritySummary(BaseModel):
    total_records: int
    verified_records: int
    tamper_detected: int
    custody_events: int


class IndicatorStatsSummary(BaseModel):
    ipv4_count: int = 0
    ipv6_count: int = 0
    domain_count: int = 0
    hash_count: int = 0
    file_path_count: int = 0
    process_name_count: int = 0
    port_count: int = 0
    recent_indicators: List[Dict[str, Any]] = []


class RecentJobSummary(BaseModel):
    job_id: str
    name: str
    agent_id: str
    hostname: str
    status: str
    detection_enabled: bool
    created_at: datetime
    completed_at: Optional[datetime] = None


class CommandCenterResponse(BaseModel):
    platform_status: str
    version: str
    summary: CommandCenterSummary
    systems: List[SystemNode]
    adversary_matrix: Dict[str, MatrixCategory]
    cross_system_correlations: List[CrossSystemCorrelationSummary]
    priority_investigations: List[PriorityInvestigationSummary]
    master_timeline: List[TimelineEventSummary]
    evidence_integrity: EvidenceIntegritySummary
    indicator_stats: IndicatorStatsSummary
    recent_jobs: List[RecentJobSummary]
