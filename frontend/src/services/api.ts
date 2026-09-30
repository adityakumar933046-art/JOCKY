import {
  Agent,
  Job,
  EvidenceRecord,
  Finding,
  Investigation,
  TimelineResponse,
  CompilerValidationResponse,
  AuthUser,
  LoginResponse,
  AuditLog,
  SecurityEvent,
  SecurityMetrics,
  CustodyEvent,
  NormalizedArtifact,
  ArtifactRelationship,
  Indicator,
  CrossSystemCorrelation,
  CorrelatedFinding,
  InvestigationGraph,
  InvestigationNote,
  InvestigationSnapshot,
  SearchResponse,
} from '../types/api';

const API_BASE = ((import.meta as any).env?.VITE_API_BASE_URL as string) || '/api/v1';
const ANALYST_KEY = 'jocky-analyst-secret-key-2026';

export const getAuthToken = (): string | null => {
  return localStorage.getItem('jocky_access_token');
};

export const setAuthToken = (token: string): void => {
  localStorage.setItem('jocky_access_token', token);
};

export const removeAuthToken = (): void => {
  localStorage.removeItem('jocky_access_token');
  localStorage.removeItem('jocky_user');
};

const getHeaders = (extraHeaders: Record<string, string> = {}): Record<string, string> => {
  const token = getAuthToken();
  const baseHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Analyst-Key': ANALYST_KEY,
    ...extraHeaders,
  };
  if (token) {
    baseHeaders['Authorization'] = `Bearer ${token}`;
  }
  return baseHeaders;
};

export const api = {
  // Agents
  async getAgents(): Promise<Agent[]> {
    const res = await fetch(`${API_BASE}/agents`);
    if (!res.ok) throw new Error('Failed to load agents');
    return res.json();
  },

  async getAgent(agentId: string): Promise<Agent> {
    const res = await fetch(`${API_BASE}/agents/${agentId}`);
    if (!res.ok) throw new Error('Failed to load agent details');
    return res.json();
  },

  // Jobs
  async getJobs(params?: { agent_id?: string; status?: string }): Promise<Job[]> {
    const url = new URL(`${API_BASE}/jobs`, window.location.origin);
    if (params?.agent_id) url.searchParams.set('agent_id', params.agent_id);
    if (params?.status) url.searchParams.set('status', params.status);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error('Failed to load jobs');
    return res.json();
  },

  async createJob(payload: {
    name: string;
    agent_id: string;
    jocky_source: string;
    detection_enabled: boolean;
  }): Promise<Job> {
    const res = await fetch(`${API_BASE}/jobs`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create job' }));
      throw new Error(err.detail || 'Failed to create job');
    }
    return res.json();
  },

  // Compiler Validation
  async validateJocky(source: string): Promise<CompilerValidationResponse> {
    const res = await fetch(`${API_BASE}/compiler/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source }),
    });
    if (!res.ok) throw new Error('Validation request failed');
    return res.json();
  },

  // Evidence
  async getEvidence(params?: { agent_id?: string; job_id?: string; operation?: string }): Promise<EvidenceRecord[]> {
    const url = new URL(`${API_BASE}/evidence`, window.location.origin);
    if (params?.agent_id) url.searchParams.set('agent_id', params.agent_id);
    if (params?.job_id) url.searchParams.set('job_id', params.job_id);
    if (params?.operation) url.searchParams.set('operation', params.operation);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error('Failed to load evidence');
    return res.json();
  },

  // Findings
  async getFindings(params?: {
    agent_id?: string;
    job_id?: string;
    severity?: string;
    category?: string;
    rule_id?: string;
  }): Promise<Finding[]> {
    const url = new URL(`${API_BASE}/findings`, window.location.origin);
    if (params?.agent_id) url.searchParams.set('agent_id', params.agent_id);
    if (params?.job_id) url.searchParams.set('job_id', params.job_id);
    if (params?.severity) url.searchParams.set('severity', params.severity);
    if (params?.category) url.searchParams.set('category', params.category);
    if (params?.rule_id) url.searchParams.set('rule_id', params.rule_id);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error('Failed to load findings');
    return res.json();
  },

  // Investigations
  async getInvestigations(): Promise<Investigation[]> {
    const res = await fetch(`${API_BASE}/investigations`);
    if (!res.ok) throw new Error('Failed to load investigations');
    return res.json();
  },

  async getInvestigation(id: string): Promise<Investigation> {
    const res = await fetch(`${API_BASE}/investigations/${id}`);
    if (!res.ok) throw new Error('Failed to load investigation');
    return res.json();
  },

  async createInvestigation(payload: {
    title: string;
    description?: string;
    assigned_analyst?: string;
    agent_ids?: string[];
    job_ids?: string[];
    evidence_ids?: string[];
    finding_ids?: string[];
  }): Promise<Investigation> {
    const res = await fetch(`${API_BASE}/investigations`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to create investigation');
    return res.json();
  },

  async updateInvestigation(
    id: string,
    payload: {
      status?: string;
      description?: string;
      agent_ids?: string[];
      job_ids?: string[];
      evidence_ids?: string[];
      finding_ids?: string[];
    }
  ): Promise<Investigation> {
    const res = await fetch(`${API_BASE}/investigations/${id}`, {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to update investigation');
    return res.json();
  },

  async getTimeline(id: string): Promise<TimelineResponse> {
    const res = await fetch(`${API_BASE}/investigations/${id}/timeline`);
    if (!res.ok) throw new Error('Failed to load timeline');
    return res.json();
  },

  // Agent Trust Lifecycle
  async approveAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/approve`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to approve agent' }));
      throw new Error(err.detail || 'Failed to approve agent');
    }
    return res.json();
  },

  async suspendAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/suspend`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to suspend agent' }));
      throw new Error(err.detail || 'Failed to suspend agent');
    }
    return res.json();
  },

  async revokeAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(`${API_BASE}/agents/${agentId}/revoke`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to revoke agent' }));
      throw new Error(err.detail || 'Failed to revoke agent');
    }
    return res.json();
  },

  // Authentication
  async login(username: string, password: string): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(err.detail || 'Login failed');
    }
    const data: LoginResponse = await res.json();
    setAuthToken(data.access_token);
    localStorage.setItem('jocky_user', JSON.stringify({
      user_id: data.user_id,
      username: data.username,
      role: data.role,
      organization_id: data.organization_id,
    }));
    return data;
  },

  async logout(): Promise<void> {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: getHeaders(),
      });
    } finally {
      removeAuthToken();
    }
  },

  async getMe(): Promise<AuthUser> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load user profile');
    return res.json();
  },

  // Security & Audit
  async getSecurityMetrics(): Promise<SecurityMetrics> {
    const res = await fetch(`${API_BASE}/security/metrics`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load security metrics');
    return res.json();
  },

  async getSecurityEvents(params?: { event_type?: string; severity?: string; limit?: number }): Promise<SecurityEvent[]> {
    const url = new URL(`${API_BASE}/security/events`, window.location.origin);
    if (params?.event_type) url.searchParams.set('event_type', params.event_type);
    if (params?.severity) url.searchParams.set('severity', params.severity);
    if (params?.limit) url.searchParams.set('limit', params.limit.toString());
    const res = await fetch(url.toString(), {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load security events');
    return res.json();
  },

  async getAuditLogs(params?: { actor_id?: string; action?: string; limit?: number }): Promise<AuditLog[]> {
    const url = new URL(`${API_BASE}/audit`, window.location.origin);
    if (params?.actor_id) url.searchParams.set('actor_id', params.actor_id);
    if (params?.action) url.searchParams.set('action', params.action);
    if (params?.limit) url.searchParams.set('limit', params.limit.toString());
    const res = await fetch(url.toString(), {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load audit logs');
    return res.json();
  },

  async getEvidenceCustody(evidenceId: string): Promise<CustodyEvent[]> {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/custody`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load chain of custody');
    return res.json();
  },

  getReportUrl(id: string, format: 'html' | 'json' = 'html'): string {
    return `${API_BASE}/investigations/${id}/report?format=${format}`;
  },

  // Forensics Normalization & Artifacts
  async getArtifacts(params?: { artifact_type?: string; agent_id?: string; evidence_id?: string; search?: string; limit?: number }): Promise<NormalizedArtifact[]> {
    const url = new URL(`${API_BASE}/artifacts`, window.location.origin);
    if (params?.artifact_type) url.searchParams.set('artifact_type', params.artifact_type);
    if (params?.agent_id) url.searchParams.set('agent_id', params.agent_id);
    if (params?.evidence_id) url.searchParams.set('evidence_id', params.evidence_id);
    if (params?.search) url.searchParams.set('search', params.search);
    if (params?.limit) url.searchParams.set('limit', params.limit.toString());
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load normalized artifacts');
    return res.json();
  },

  async getArtifact(artifactId: string): Promise<NormalizedArtifact> {
    const res = await fetch(`${API_BASE}/artifacts/${artifactId}`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load artifact');
    return res.json();
  },

  async getRelationships(params?: { source_id?: string; target_id?: string; relationship_type?: string }): Promise<ArtifactRelationship[]> {
    const url = new URL(`${API_BASE}/relationships`, window.location.origin);
    if (params?.source_id) url.searchParams.set('source_artifact_id', params.source_id);
    if (params?.target_id) url.searchParams.set('target_artifact_id', params.target_id);
    if (params?.relationship_type) url.searchParams.set('relationship_type', params.relationship_type);
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load artifact relationships');
    return res.json();
  },

  // Indicators (IOCs)
  async getIndicators(params?: { indicator_type?: string; severity?: string; min_occurrences?: number; search?: string; limit?: number }): Promise<Indicator[]> {
    const url = new URL(`${API_BASE}/indicators`, window.location.origin);
    if (params?.indicator_type) url.searchParams.set('indicator_type', params.indicator_type);
    if (params?.severity) url.searchParams.set('severity', params.severity);
    if (params?.min_occurrences) url.searchParams.set('min_occurrences', params.min_occurrences.toString());
    if (params?.search) url.searchParams.set('search', params.search);
    if (params?.limit) url.searchParams.set('limit', params.limit.toString());
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load forensic indicators');
    return res.json();
  },

  async getIndicator(indicatorId: string): Promise<Indicator> {
    const res = await fetch(`${API_BASE}/indicators/${indicatorId}`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load indicator details');
    return res.json();
  },

  // Correlation & Cross-System Findings
  async getCrossSystemCorrelations(params?: { indicator_type?: string; severity?: string; search?: string }): Promise<CrossSystemCorrelation[]> {
    const url = new URL(`${API_BASE}/correlation/cross-system`, window.location.origin);
    if (params?.indicator_type) url.searchParams.set('indicator_type', params.indicator_type);
    if (params?.severity) url.searchParams.set('severity', params.severity);
    if (params?.search) url.searchParams.set('search', params.search);
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load cross-system correlations');
    return res.json();
  },

  async getCorrelatedFindings(params?: { category?: string; severity?: string }): Promise<CorrelatedFinding[]> {
    const url = new URL(`${API_BASE}/correlation/findings`, window.location.origin);
    if (params?.category) url.searchParams.set('category', params.category);
    if (params?.severity) url.searchParams.set('severity', params.severity);
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load correlated findings');
    return res.json();
  },

  async runCorrelation(): Promise<Record<string, any>> {
    const res = await fetch(`${API_BASE}/correlation/run`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to execute correlation analysis');
    return res.json();
  },

  // Investigation Workspace Extensions
  async getInvestigationGraph(investigationId: string): Promise<InvestigationGraph> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/graph`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load investigation graph');
    return res.json();
  },

  async getInvestigationArtifacts(investigationId: string): Promise<NormalizedArtifact[]> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/artifacts`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load investigation artifacts');
    return res.json();
  },

  async getInvestigationIndicators(investigationId: string): Promise<Indicator[]> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/indicators`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load investigation indicators');
    return res.json();
  },

  async getInvestigationNotes(investigationId: string): Promise<InvestigationNote[]> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/notes`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load investigation notes');
    return res.json();
  },

  async addInvestigationNote(investigationId: string, content: string): Promise<InvestigationNote> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/notes`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ content }),
    });
    if (!res.ok) throw new Error('Failed to add note');
    return res.json();
  },

  async deleteInvestigationNote(investigationId: string, noteId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/notes/${noteId}`, {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to delete note');
  },

  async createInvestigationSnapshot(investigationId: string, title: string): Promise<InvestigationSnapshot> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/snapshots`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ title }),
    });
    if (!res.ok) throw new Error('Failed to capture snapshot');
    return res.json();
  },

  async getInvestigationSnapshots(investigationId: string): Promise<InvestigationSnapshot[]> {
    const res = await fetch(`${API_BASE}/investigations/${investigationId}/snapshots`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to load snapshots');
    return res.json();
  },

  // Forensic Search
  async search(query: string): Promise<SearchResponse> {
    const url = new URL(`${API_BASE}/search`, window.location.origin);
    url.searchParams.set('q', query);
    const res = await fetch(url.toString(), { headers: getHeaders() });
    if (!res.ok) throw new Error('Search failed');
    return res.json();
  },
};
