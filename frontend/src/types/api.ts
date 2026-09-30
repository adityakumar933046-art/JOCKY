export interface Agent {
  agent_id: string;
  hostname: string;
  operating_system: string;
  os_version?: string;
  architecture?: string;
  jocky_version: string;
  collector_version: string;
  registered_at: string;
  last_seen: string;
  status: 'ONLINE' | 'OFFLINE';
  organization_id?: string;
  trust_state: 'PENDING' | 'AUTHORIZED' | 'SUSPENDED' | 'REVOKED';
}

export interface Job {
  job_id: string;
  name: string;
  agent_id: string;
  created_at: string;
  created_by: string;
  status: 'PENDING' | 'ASSIGNED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  jocky_source: string;
  submitted_at?: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  detection_enabled: boolean;
}

export interface EvidenceRecord {
  evidence_id: string;
  agent_id: string;
  job_id?: string;
  hostname: string;
  timestamp: string;
  operation: string;
  collection_status: string;
  data: any;
  content_hash?: string;
  hash_algorithm?: string;
  integrity_verified?: boolean;
  organization_id?: string;
}

export interface Finding {
  finding_id: string;
  agent_id: string;
  job_id?: string;
  rule_id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  description?: string;
  evidence_ids: string[];
  affected_object?: string;
  indicators: Record<string, any>;
  recommendation?: string;
  timestamp: string;
}

export interface Investigation {
  investigation_id: string;
  title: string;
  description?: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'CLOSED';
  created_at: string;
  updated_at: string;
  created_by: string;
  assigned_analyst?: string;
  agents: Agent[];
  jobs: Job[];
  evidence: EvidenceRecord[];
  findings: Finding[];
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  summary: string;
  details: Record<string, any>;
}

export interface TimelineResponse {
  investigation_id: string;
  title: string;
  total_events: number;
  events: TimelineEvent[];
}

export interface CompilerValidationResponse {
  valid: boolean;
  errors: string[];
  diagnostics: Array<{ message: string; line?: number; column?: number }>;
  tokens_count: number;
  instructions_count: number;
}

export interface AuthUser {
  user_id: string;
  username: string;
  email: string;
  role: string;
  organization_id: string;
  permissions: string[];
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user_id: string;
  username: string;
  role: string;
  organization_id: string;
}

export interface AuditLog {
  audit_id: string;
  timestamp: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  organization_id: string;
  ip_address?: string;
  result: 'SUCCESS' | 'FAILURE' | 'ERROR';
  details?: Record<string, any>;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  actor_id?: string;
  organization_id?: string;
  source_ip?: string;
  details?: Record<string, any>;
}

export interface SecurityMetrics {
  total_users: number;
  active_users: number;
  locked_accounts: number;
  total_agents: number;
  agents_by_trust: Record<string, number>;
  security_events_last_24h: number;
  failed_logins_last_24h: number;
  integrity_violations: number;
}

export interface CustodyEvent {
  event_id: string;
  evidence_id: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  action: string;
  hash_at_event: string;
  previous_event_hash: string;
  signature: string;
  details?: Record<string, any>;
}

export interface NormalizedArtifact {
  artifact_id: string;
  organization_id: string;
  agent_id: string;
  evidence_id: string;
  job_id?: string;
  hostname: string;
  artifact_type: string;
  timestamp: string;
  normalized_attributes: Record<string, any>;
  indicators: string[];
  created_at?: string;
}

export interface ArtifactRelationship {
  relationship_id: string;
  organization_id: string;
  source_artifact_id: string;
  target_artifact_id: string;
  relationship_type: string;
  confidence: number;
  evidence_ids: string[];
  metadata_json: Record<string, any>;
  created_at?: string;
}

export interface Indicator {
  indicator_id: string;
  organization_id: string;
  indicator_type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  source_artifacts: string[];
  agents_observed: string[];
  metadata_json: Record<string, any>;
}

export interface CrossSystemCorrelation {
  correlation_id: string;
  organization_id: string;
  indicator_type: string;
  indicator_value: string;
  agents_count: number;
  agent_ids: string[];
  first_seen: string;
  last_seen: string;
  occurrences: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  linked_investigation_ids: string[];
  details: Record<string, any>;
  created_at?: string;
}

export interface CorrelatedFinding {
  correlation_id: string;
  organization_id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  description?: string;
  finding_ids: string[];
  artifact_ids: string[];
  indicator_ids: string[];
  agent_ids: string[];
  created_at?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity: string;
  agent_id?: string;
  metadata: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  confidence: number;
  evidence_ids: string[];
  metadata: Record<string, any>;
}

export interface InvestigationGraph {
  investigation_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  metrics: {
    node_count: number;
    edge_count: number;
    entities_by_type: Record<string, number>;
    highest_severity: string;
  };
}

export interface InvestigationNote {
  note_id: string;
  investigation_id: string;
  organization_id: string;
  author_id: string;
  author_name: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface InvestigationSnapshot {
  snapshot_id: string;
  investigation_id: string;
  organization_id: string;
  title: string;
  created_by: string;
  created_at: string;
  snapshot_data: Record<string, any>;
}

export interface SearchResultItem {
  entity_type: string;
  entity_id: string;
  title: string;
  subtitle: string;
  severity?: string;
  timestamp?: string;
  metadata: Record<string, any>;
}

export interface SearchResponse {
  query: string;
  total_results: number;
  results: SearchResultItem[];
}

export interface SystemNode {
  agent_id: string;
  hostname: string;
  operating_system: string;
  os_version?: string;
  architecture?: string;
  status: 'ONLINE' | 'OFFLINE' | string;
  trust_state: 'PENDING' | 'AUTHORIZED' | 'SUSPENDED' | 'REVOKED' | string;
  last_seen?: string;
  evidence_count: number;
  findings_count: number;
  max_severity: string;
}

export interface MatrixCategory {
  low: number;
  medium: number;
  high: number;
  critical: number;
  total: number;
}

export interface CommandCenterSummary {
  total_systems: number;
  online_systems: number;
  offline_systems: number;
  trusted_systems: number;
  total_jobs: number;
  active_jobs: number;
  total_evidence: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  total_indicators: number;
  total_correlations: number;
  total_investigations: number;
  last_analysis_timestamp?: string;
}

export interface TimelineEventSummary {
  id: string;
  timestamp: string;
  event_type: string;
  hostname: string;
  summary: string;
  severity: string;
  category?: string;
  details: Record<string, any>;
}

export interface CrossSystemCorrelationSummary {
  correlation_id: string;
  indicator_type: string;
  indicator_value: string;
  agents_count: number;
  agent_ids: string[];
  severity: string;
  first_seen?: string;
  last_seen?: string;
  occurrences: number;
}

export interface PriorityInvestigationSummary {
  investigation_id: string;
  title: string;
  description?: string;
  status: string;
  assigned_analyst?: string;
  created_at: string;
  systems_count: number;
  findings_count: number;
  evidence_count: number;
  max_severity: string;
}

export interface EvidenceIntegritySummary {
  total_records: number;
  verified_records: number;
  tamper_detected: number;
  custody_events: number;
  verified_percentage: number;
  last_verification_timestamp?: string;
}

export interface IndicatorStatsSummary {
  total_indicators: number;
  new_indicators: number;
  correlated_indicators: number;
  systems_affected: number;
  ipv4_count: number;
  ipv6_count: number;
  domain_count: number;
  hash_count: number;
  file_path_count: number;
  process_name_count: number;
  port_count: number;
  recent_indicators: Array<Record<string, any>>;
}

export interface RecentJobSummary {
  job_id: string;
  name: string;
  agent_id: string;
  hostname: string;
  status: string;
  detection_enabled: boolean;
  findings_generated: number;
  created_at: string;
  completed_at?: string;
}

export interface ReportSummary {
  report_id: string;
  investigation_id: string;
  investigation_title: string;
  generated_by: string;
  generated_at: string;
  evidence_count: number;
  finding_count: number;
  integrity_status: string;
}

export interface CommandCenterTelemetry {
  platform_status: string;
  version: string;
  summary: CommandCenterSummary;
  systems: SystemNode[];
  adversary_matrix: Record<string, MatrixCategory>;
  cross_system_correlations: CrossSystemCorrelationSummary[];
  priority_investigations: PriorityInvestigationSummary[];
  master_timeline: TimelineEventSummary[];
  evidence_integrity: EvidenceIntegritySummary;
  indicator_stats: IndicatorStatsSummary;
  recent_jobs: RecentJobSummary[];
  reports: ReportSummary[];
}

