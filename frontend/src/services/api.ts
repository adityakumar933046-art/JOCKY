import {
  Agent,
  Job,
  EvidenceRecord,
  Finding,
  Investigation,
  TimelineResponse,
  AuthUser,
  LoginResponse,
  SecurityMetrics,
  SecurityEvent,
  AuditLog,
  CustodyEvent,
  CompilerValidationResponse,
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

const ANALYST_KEY = 'jocky-analyst-secret-key-2026';

export const getApiBaseUrl = (): string => {
  const custom = localStorage.getItem('jocky_api_base');
  if (custom && custom.trim()) {
    let url = custom.trim().replace(/\/+$/, '');
    if (!url.endsWith('/api/v1')) {
      url = `${url}/api/v1`;
    }
    return url;
  }
  const envUrl = ((import.meta as any).env?.VITE_API_BASE_URL as string);
  if (envUrl && envUrl.trim()) {
    let url = envUrl.trim().replace(/\/+$/, '');
    if (!url.endsWith('/api/v1')) {
      url = `${url}/api/v1`;
    }
    return url;
  }

  // 3. Smart fallback when deployed on Vercel: use active HTTPS live cloud backend
  if (typeof window !== 'undefined' && window.location.hostname.includes('vercel.app')) {
    return 'https://plaintiff-robin-blanket-refer.trycloudflare.com/api/v1';
  }

  return '/api/v1';
};

export const setApiBaseUrl = (url: string | null): void => {
  if (!url || !url.trim()) {
    localStorage.removeItem('jocky_api_base');
  } else {
    let clean = url.trim().replace(/\/+$/, '');
    if (!clean.endsWith('/api/v1')) {
      clean = `${clean}/api/v1`;
    }
    localStorage.setItem('jocky_api_base', clean);
  }
};

export const resolveUrl = (path: string, params?: Record<string, string | number | undefined>): string => {
  const base = getApiBaseUrl();
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const full = `${base}${cleanPath}`;
  const url = new URL(full, window.location.origin);
  if (params) {
    for (const [key, val] of Object.entries(params)) {
      if (val !== undefined && val !== null && val !== '') {
        url.searchParams.set(key, String(val));
      }
    }
  }
  return url.toString();
};

export const handleResponse = async <T>(res: Response, fallbackError = 'Request failed'): Promise<T> => {
  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    const text = await res.text();
    if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html') || text.trim().startsWith('<script')) {
      throw new Error(
        'Backend API endpoint not connected. The application received HTML from Vercel instead of JSON. Please configure your Render Backend URL using the "Backend API" button in the header.'
      );
    }
    throw new Error(`Server returned non-JSON response (${res.status}): ${text.slice(0, 100)}`);
  }

  if (!res.ok) {
    let detail = fallbackError;
    try {
      const errJson = await res.json();
      detail = errJson.detail || errJson.message || fallbackError;
    } catch {
      detail = `HTTP ${res.status}: ${res.statusText || fallbackError}`;
    }
    throw new Error(detail);
  }

  try {
    return (await res.json()) as T;
  } catch (parseErr: any) {
    throw new Error(
      'Backend response was not valid JSON. Please check backend connection in API Settings.'
    );
  }
};

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
  // Health & Connectivity Test
  async testConnection(targetUrl?: string): Promise<{ ok: boolean; status?: string; message?: string }> {
    let testEndpoint = targetUrl ? targetUrl.trim().replace(/\/+$/, '') : getApiBaseUrl();
    if (testEndpoint.endsWith('/api/v1')) {
      testEndpoint = testEndpoint.slice(0, -7);
    }
    const fullHealthUrl = `${testEndpoint}/health`;
    try {
      const res = await fetch(fullHealthUrl, { method: 'GET', headers: { Accept: 'application/json' } });
      const contentType = res.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        return { ok: false, message: 'Endpoint returned HTML instead of JSON. Make sure URL points to your Render backend.' };
      }
      if (!res.ok) {
        return { ok: false, message: `Server responded with HTTP ${res.status}` };
      }
      const data = await res.json();
      return { ok: true, status: data.status, message: `Connected! Service: ${data.service || 'JOCKY'} v${data.version || '1.0.0'}` };
    } catch (err: any) {
      return { ok: false, message: err.message || 'Connection failed (CORS or network error)' };
    }
  },

  // Agents
  async getAgents(): Promise<Agent[]> {
    const res = await fetch(resolveUrl('/agents'));
    return handleResponse<Agent[]>(res, 'Failed to load agents');
  },

  async getAgent(agentId: string): Promise<Agent> {
    const res = await fetch(resolveUrl(`/agents/${agentId}`));
    return handleResponse<Agent>(res, 'Failed to load agent details');
  },

  // Jobs
  async getJobs(params?: { agent_id?: string; status?: string }): Promise<Job[]> {
    const res = await fetch(resolveUrl('/jobs', params));
    return handleResponse<Job[]>(res, 'Failed to load jobs');
  },

  async createJob(payload: {
    name: string;
    agent_id: string;
    jocky_source: string;
    detection_enabled: boolean;
  }): Promise<Job> {
    const res = await fetch(resolveUrl('/jobs'), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return handleResponse<Job>(res, 'Failed to create job');
  },

  // Compiler Validation
  async validateJocky(source: string): Promise<CompilerValidationResponse> {
    const res = await fetch(resolveUrl('/compiler/validate'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source }),
    });
    return handleResponse<CompilerValidationResponse>(res, 'Validation request failed');
  },

  // Evidence
  async getEvidence(params?: { agent_id?: string; job_id?: string; operation?: string }): Promise<EvidenceRecord[]> {
    const res = await fetch(resolveUrl('/evidence', params));
    return handleResponse<EvidenceRecord[]>(res, 'Failed to load evidence');
  },

  // Findings
  async getFindings(params?: {
    agent_id?: string;
    job_id?: string;
    severity?: string;
    category?: string;
    rule_id?: string;
  }): Promise<Finding[]> {
    const res = await fetch(resolveUrl('/findings', params));
    return handleResponse<Finding[]>(res, 'Failed to load findings');
  },

  // Investigations
  async getInvestigations(): Promise<Investigation[]> {
    const res = await fetch(resolveUrl('/investigations'));
    return handleResponse<Investigation[]>(res, 'Failed to load investigations');
  },

  async getInvestigation(id: string): Promise<Investigation> {
    const res = await fetch(resolveUrl(`/investigations/${id}`));
    return handleResponse<Investigation>(res, 'Failed to load investigation');
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
    const res = await fetch(resolveUrl('/investigations'), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return handleResponse<Investigation>(res, 'Failed to create investigation');
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
    const res = await fetch(resolveUrl(`/investigations/${id}`), {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    return handleResponse<Investigation>(res, 'Failed to update investigation');
  },

  async getTimeline(id: string): Promise<TimelineResponse> {
    const res = await fetch(resolveUrl(`/investigations/${id}/timeline`));
    return handleResponse<TimelineResponse>(res, 'Failed to load timeline');
  },

  // Agent Trust Lifecycle
  async approveAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(resolveUrl(`/agents/${agentId}/approve`), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    return handleResponse<Agent>(res, 'Failed to approve agent');
  },

  async suspendAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(resolveUrl(`/agents/${agentId}/suspend`), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    return handleResponse<Agent>(res, 'Failed to suspend agent');
  },

  async revokeAgent(agentId: string, reason?: string): Promise<Agent> {
    const res = await fetch(resolveUrl(`/agents/${agentId}/revoke`), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    return handleResponse<Agent>(res, 'Failed to revoke agent');
  },

  // Authentication
  async login(username: string, password: string): Promise<LoginResponse> {
    const res = await fetch(resolveUrl('/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await handleResponse<LoginResponse>(res, 'Login failed');
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
      await fetch(resolveUrl('/auth/logout'), {
        method: 'POST',
        headers: getHeaders(),
      });
    } finally {
      removeAuthToken();
    }
  },

  async getMe(): Promise<AuthUser> {
    const res = await fetch(resolveUrl('/auth/me'), {
      headers: getHeaders(),
    });
    return handleResponse<AuthUser>(res, 'Failed to load user profile');
  },

  // Security & Audit
  async getSecurityMetrics(): Promise<SecurityMetrics> {
    const res = await fetch(resolveUrl('/security/metrics'), {
      headers: getHeaders(),
    });
    return handleResponse<SecurityMetrics>(res, 'Failed to load security metrics');
  },

  async getSecurityEvents(params?: { event_type?: string; severity?: string; limit?: number }): Promise<SecurityEvent[]> {
    const res = await fetch(resolveUrl('/security/events', params), {
      headers: getHeaders(),
    });
    return handleResponse<SecurityEvent[]>(res, 'Failed to load security events');
  },

  async getAuditLogs(params?: { actor_id?: string; action?: string; limit?: number }): Promise<AuditLog[]> {
    const res = await fetch(resolveUrl('/audit', params), {
      headers: getHeaders(),
    });
    return handleResponse<AuditLog[]>(res, 'Failed to load audit logs');
  },

  async getEvidenceCustody(evidenceId: string): Promise<CustodyEvent[]> {
    const res = await fetch(resolveUrl(`/evidence/${evidenceId}/custody`), {
      headers: getHeaders(),
    });
    return handleResponse<CustodyEvent[]>(res, 'Failed to load chain of custody');
  },

  getReportUrl(id: string, format: 'html' | 'json' = 'html'): string {
    return resolveUrl(`/investigations/${id}/report`, { format });
  },

  // Forensics Normalization & Artifacts
  async getArtifacts(params?: { artifact_type?: string; agent_id?: string; evidence_id?: string; search?: string; limit?: number }): Promise<NormalizedArtifact[]> {
    const res = await fetch(resolveUrl('/artifacts', params), { headers: getHeaders() });
    return handleResponse<NormalizedArtifact[]>(res, 'Failed to load normalized artifacts');
  },

  async getArtifact(artifactId: string): Promise<NormalizedArtifact> {
    const res = await fetch(resolveUrl(`/artifacts/${artifactId}`), { headers: getHeaders() });
    return handleResponse<NormalizedArtifact>(res, 'Failed to load artifact');
  },

  async getRelationships(params?: { source_id?: string; target_id?: string; relationship_type?: string }): Promise<ArtifactRelationship[]> {
    const res = await fetch(resolveUrl('/relationships', params), { headers: getHeaders() });
    return handleResponse<ArtifactRelationship[]>(res, 'Failed to load artifact relationships');
  },

  // Indicators (IOCs)
  async getIndicators(params?: { indicator_type?: string; severity?: string; min_occurrences?: number; search?: string; limit?: number }): Promise<Indicator[]> {
    const res = await fetch(resolveUrl('/indicators', params), { headers: getHeaders() });
    return handleResponse<Indicator[]>(res, 'Failed to load forensic indicators');
  },

  async getIndicator(indicatorId: string): Promise<Indicator> {
    const res = await fetch(resolveUrl(`/indicators/${indicatorId}`), { headers: getHeaders() });
    return handleResponse<Indicator>(res, 'Failed to load indicator details');
  },

  // Correlation & Cross-System Findings
  async getCrossSystemCorrelations(params?: { indicator_type?: string; severity?: string; search?: string }): Promise<CrossSystemCorrelation[]> {
    const res = await fetch(resolveUrl('/correlation/cross-system', params), { headers: getHeaders() });
    return handleResponse<CrossSystemCorrelation[]>(res, 'Failed to load cross-system correlations');
  },

  async getCorrelatedFindings(params?: { category?: string; severity?: string }): Promise<CorrelatedFinding[]> {
    const res = await fetch(resolveUrl('/correlation/findings', params), { headers: getHeaders() });
    return handleResponse<CorrelatedFinding[]>(res, 'Failed to load correlated findings');
  },

  async runCorrelation(): Promise<Record<string, any>> {
    const res = await fetch(resolveUrl('/correlation/run'), {
      method: 'POST',
      headers: getHeaders(),
    });
    return handleResponse<Record<string, any>>(res, 'Failed to execute correlation analysis');
  },

  // Investigation Workspace Extensions
  async getInvestigationGraph(investigationId: string): Promise<InvestigationGraph> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/graph`), { headers: getHeaders() });
    return handleResponse<InvestigationGraph>(res, 'Failed to load investigation graph');
  },

  async getInvestigationArtifacts(investigationId: string): Promise<NormalizedArtifact[]> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/artifacts`), { headers: getHeaders() });
    return handleResponse<NormalizedArtifact[]>(res, 'Failed to load investigation artifacts');
  },

  async getInvestigationIndicators(investigationId: string): Promise<Indicator[]> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/indicators`), { headers: getHeaders() });
    return handleResponse<Indicator[]>(res, 'Failed to load investigation indicators');
  },

  async getInvestigationNotes(investigationId: string): Promise<InvestigationNote[]> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/notes`), { headers: getHeaders() });
    return handleResponse<InvestigationNote[]>(res, 'Failed to load investigation notes');
  },

  async addInvestigationNote(investigationId: string, content: string): Promise<InvestigationNote> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/notes`), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ content }),
    });
    return handleResponse<InvestigationNote>(res, 'Failed to add note');
  },

  async deleteInvestigationNote(investigationId: string, noteId: string): Promise<void> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/notes/${noteId}`), {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to delete note');
  },

  async createInvestigationSnapshot(investigationId: string, title: string): Promise<InvestigationSnapshot> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/snapshots`), {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ title }),
    });
    return handleResponse<InvestigationSnapshot>(res, 'Failed to capture snapshot');
  },

  async getInvestigationSnapshots(investigationId: string): Promise<InvestigationSnapshot[]> {
    const res = await fetch(resolveUrl(`/investigations/${investigationId}/snapshots`), { headers: getHeaders() });
    return handleResponse<InvestigationSnapshot[]>(res, 'Failed to load snapshots');
  },

  // Forensic Search
  async search(query: string): Promise<SearchResponse> {
    const res = await fetch(resolveUrl('/search', { q: query }), { headers: getHeaders() });
    return handleResponse<SearchResponse>(res, 'Search failed');
  },
};
