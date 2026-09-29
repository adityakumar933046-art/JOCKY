import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Agent, Job, EvidenceRecord, Finding } from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { Modal } from '../components/Modal';
import { Server, Monitor, Clock, PlaySquare, FileSearch, ShieldAlert, Cpu } from 'lucide-react';

export const SystemsPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  // Drilldown state
  const [agentJobs, setAgentJobs] = useState<Job[]>([]);
  const [agentEvidence, setAgentEvidence] = useState<EvidenceRecord[]>([]);
  const [agentFindings, setAgentFindings] = useState<Finding[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'jobs' | 'evidence' | 'findings'>('overview');
  const [drilldownLoading, setDrilldownLoading] = useState(false);

  const loadAgents = async () => {
    try {
      setLoading(true);
      const data = await api.getAgents();
      setAgents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAgents();
  }, []);

  const handleApprove = async (agentId: string) => {
    try {
      await api.approveAgent(agentId, 'Approved via dashboard');
      await loadAgents();
      if (selectedAgent && selectedAgent.agent_id === agentId) {
        setSelectedAgent({ ...selectedAgent, trust_state: 'AUTHORIZED', status: 'ONLINE' });
      }
    } catch (err: any) {
      alert(err.message || 'Failed to approve agent');
    }
  };

  const handleSuspend = async (agentId: string) => {
    try {
      await api.suspendAgent(agentId, 'Suspended via dashboard');
      await loadAgents();
      if (selectedAgent && selectedAgent.agent_id === agentId) {
        setSelectedAgent({ ...selectedAgent, trust_state: 'SUSPENDED' });
      }
    } catch (err: any) {
      alert(err.message || 'Failed to suspend agent');
    }
  };

  const handleRevoke = async (agentId: string) => {
    if (!window.confirm(`Are you sure you want to permanently REVOKE agent '${agentId}'? This action cannot be undone.`)) {
      return;
    }
    try {
      await api.revokeAgent(agentId, 'Revoked via dashboard');
      await loadAgents();
      if (selectedAgent && selectedAgent.agent_id === agentId) {
        setSelectedAgent({ ...selectedAgent, trust_state: 'REVOKED', status: 'OFFLINE' });
      }
    } catch (err: any) {
      alert(err.message || 'Failed to revoke agent');
    }
  };

  const openDrilldown = async (agent: Agent) => {
    setSelectedAgent(agent);
    setActiveTab('overview');
    setDrilldownLoading(true);
    try {
      const [jobs, evidence, findings] = await Promise.all([
        api.getJobs({ agent_id: agent.agent_id }),
        api.getEvidence({ agent_id: agent.agent_id }),
        api.getFindings({ agent_id: agent.agent_id }),
      ]);
      setAgentJobs(jobs);
      setAgentEvidence(evidence);
      setAgentFindings(findings);
    } catch (err) {
      console.error(err);
    } finally {
      setDrilldownLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Managed Systems"
        subtitle="Monitored Windows and Linux endpoints running the JOCKY agent daemon"
        onRefresh={loadAgents}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
          }}
        >
          <div
            style={{
              padding: '16px 20px',
              borderBottom: '1px solid #e2e8f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={18} color="#2563eb" />
              <span style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Enrolled Systems ({agents.length})
              </span>
            </div>
          </div>

          {agents.length === 0 ? (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <Server size={36} color="#94a3b8" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: '#0f172a' }}>No agents enrolled</div>
              <div style={{ fontSize: '13px', marginTop: '4px' }}>
                Start a JOCKY agent daemon with <code>python -m agent.agent</code> to begin monitoring.
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Trust State</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Hostname</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Operating System</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Architecture</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Agent ID</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Last Seen</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Governance Actions</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((ag) => (
                  <tr
                    key={ag.agent_id}
                    style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                    onClick={() => openDrilldown(ag)}
                  >
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge status={ag.status} type="agent" />
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span
                        style={{
                          padding: '3px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 700,
                          backgroundColor:
                            ag.trust_state === 'AUTHORIZED'
                              ? '#dcfce7'
                              : ag.trust_state === 'SUSPENDED'
                              ? '#ffedd5'
                              : ag.trust_state === 'REVOKED'
                              ? '#fee2e2'
                              : '#fef9c3',
                          color:
                            ag.trust_state === 'AUTHORIZED'
                              ? '#15803d'
                              : ag.trust_state === 'SUSPENDED'
                              ? '#c2410c'
                              : ag.trust_state === 'REVOKED'
                              ? '#b91c1c'
                              : '#a16207',
                        }}
                      >
                        {ag.trust_state || 'PENDING'}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: '#0f172a' }}>
                      {ag.hostname}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#334155' }}>
                      {ag.operating_system} {ag.os_version && `(${ag.os_version})`}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace' }}>
                      {ag.architecture || 'x86_64'}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>
                      {ag.agent_id}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b' }}>
                      {new Date(ag.last_seen).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '12px 16px' }} onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <button
                          onClick={() => openDrilldown(ag)}
                          style={{
                            padding: '4px 8px',
                            backgroundColor: '#f1f5f9',
                            border: '1px solid #cbd5e1',
                            borderRadius: '4px',
                            color: '#2563eb',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: 'pointer',
                          }}
                        >
                          Inspect
                        </button>
                        {ag.trust_state !== 'AUTHORIZED' && ag.trust_state !== 'REVOKED' && (
                          <button
                            onClick={() => handleApprove(ag.agent_id)}
                            style={{
                              padding: '4px 8px',
                              backgroundColor: '#dcfce7',
                              border: '1px solid #86efac',
                              borderRadius: '4px',
                              color: '#15803d',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                            }}
                          >
                            Approve
                          </button>
                        )}
                        {ag.trust_state === 'AUTHORIZED' && (
                          <button
                            onClick={() => handleSuspend(ag.agent_id)}
                            style={{
                              padding: '4px 8px',
                              backgroundColor: '#ffedd5',
                              border: '1px solid #fed7aa',
                              borderRadius: '4px',
                              color: '#c2410c',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                            }}
                          >
                            Suspend
                          </button>
                        )}
                        {ag.trust_state !== 'REVOKED' && (
                          <button
                            onClick={() => handleRevoke(ag.agent_id)}
                            style={{
                              padding: '4px 8px',
                              backgroundColor: '#fee2e2',
                              border: '1px solid #fca5a5',
                              borderRadius: '4px',
                              color: '#b91c1c',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                            }}
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Drilldown Modal */}
      {selectedAgent && (
        <Modal
          isOpen={!!selectedAgent}
          onClose={() => setSelectedAgent(null)}
          title={`System Drilldown: ${selectedAgent.hostname} (${selectedAgent.agent_id.substring(0, 8)})`}
          maxWidth="850px"
        >
          {/* Subheader tabs */}
          <div
            style={{
              display: 'flex',
              gap: '12px',
              borderBottom: '1px solid #e2e8f0',
              marginBottom: '20px',
              paddingBottom: '8px',
            }}
          >
            {[
              { id: 'overview', label: 'System Overview', icon: <Monitor size={16} /> },
              { id: 'jobs', label: `Jobs (${agentJobs.length})`, icon: <PlaySquare size={16} /> },
              { id: 'evidence', label: `Evidence (${agentEvidence.length})`, icon: <FileSearch size={16} /> },
              { id: 'findings', label: `Threats (${agentFindings.length})`, icon: <ShieldAlert size={16} /> },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 12px',
                  border: 'none',
                  borderBottom: activeTab === tab.id ? '2px solid #2563eb' : '2px solid transparent',
                  backgroundColor: 'transparent',
                  color: activeTab === tab.id ? '#2563eb' : '#64748b',
                  fontWeight: activeTab === tab.id ? 700 : 500,
                  fontSize: '13px',
                  cursor: 'pointer',
                }}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {drilldownLoading ? (
            <div style={{ padding: '32px', textAlign: 'center', color: '#64748b' }}>
              Loading system metrics and telemetry...
            </div>
          ) : (
            <div>
              {activeTab === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(2, 1fr)',
                      gap: '16px',
                      backgroundColor: '#f8fafc',
                      padding: '16px',
                      borderRadius: '6px',
                      border: '1px solid #e2e8f0',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>STATUS</div>
                      <div style={{ marginTop: '4px' }}>
                        <StatusBadge status={selectedAgent.status} type="agent" />
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>HOSTNAME</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: '#0f172a', marginTop: '4px' }}>
                        {selectedAgent.hostname}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>OPERATING SYSTEM</div>
                      <div style={{ fontSize: '13px', color: '#334155', marginTop: '4px' }}>
                        {selectedAgent.operating_system} {selectedAgent.os_version}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>ARCHITECTURE</div>
                      <div style={{ fontSize: '13px', fontFamily: 'monospace', color: '#334155', marginTop: '4px' }}>
                        {selectedAgent.architecture || 'x86_64'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>JOCKY VERSION</div>
                      <div style={{ fontSize: '13px', color: '#334155', marginTop: '4px' }}>
                        {selectedAgent.jocky_version}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>COLLECTOR VERSION</div>
                      <div style={{ fontSize: '13px', color: '#334155', marginTop: '4px' }}>
                        {selectedAgent.collector_version}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>FIRST REGISTERED</div>
                      <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                        {new Date(selectedAgent.registered_at).toLocaleString()}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>LAST HEARTBEAT</div>
                      <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                        {new Date(selectedAgent.last_seen).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  <div style={{ padding: '12px', backgroundColor: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '6px' }}>
                    <div style={{ fontWeight: 600, color: '#166534', fontSize: '13px' }}>Enforcement: Strict IR Allow-List</div>
                    <div style={{ fontSize: '12px', color: '#15803d', marginTop: '2px' }}>
                      This agent only executes authorized, read-only forensic operations (SYSTEM_INFO, PROCESSES, PERSISTENCE, DRIVERS, NETWORK, MEMORY, SERVICES, FILES).
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'jobs' && (
                <div>
                  {agentJobs.length === 0 ? (
                    <div style={{ padding: '24px', textAlign: 'center', color: '#64748b' }}>
                      No forensic jobs executed for this agent yet.
                    </div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                      <thead>
                        <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                          <th style={{ padding: '8px 12px' }}>Status</th>
                          <th style={{ padding: '8px 12px' }}>Name</th>
                          <th style={{ padding: '8px 12px' }}>Detection</th>
                          <th style={{ padding: '8px 12px' }}>Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {agentJobs.map((j) => (
                          <tr key={j.job_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                            <td style={{ padding: '8px 12px' }}>
                              <StatusBadge status={j.status} type="job" />
                            </td>
                            <td style={{ padding: '8px 12px', fontWeight: 600 }}>{j.name}</td>
                            <td style={{ padding: '8px 12px' }}>
                              {j.detection_enabled ? (
                                <span style={{ color: '#16a34a', fontWeight: 600 }}>Enabled</span>
                              ) : (
                                <span style={{ color: '#94a3b8' }}>Disabled</span>
                              )}
                            </td>
                            <td style={{ padding: '8px 12px', color: '#64748b' }}>
                              {new Date(j.created_at).toLocaleTimeString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {activeTab === 'evidence' && (
                <div>
                  {agentEvidence.length === 0 ? (
                    <div style={{ padding: '24px', textAlign: 'center', color: '#64748b' }}>
                      No evidence collected from this agent.
                    </div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                      <thead>
                        <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                          <th style={{ padding: '8px 12px' }}>Operation</th>
                          <th style={{ padding: '8px 12px' }}>Status</th>
                          <th style={{ padding: '8px 12px' }}>Evidence ID</th>
                          <th style={{ padding: '8px 12px' }}>Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {agentEvidence.map((ev) => (
                          <tr key={ev.evidence_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                            <td style={{ padding: '8px 12px', fontWeight: 600, color: '#0f172a' }}>
                              {ev.operation}
                            </td>
                            <td style={{ padding: '8px 12px' }}>
                              <StatusBadge status={ev.collection_status} />
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontSize: '11px', color: '#64748b' }}>
                              {ev.evidence_id}
                            </td>
                            <td style={{ padding: '8px 12px', color: '#64748b' }}>
                              {new Date(ev.timestamp).toLocaleTimeString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {activeTab === 'findings' && (
                <div>
                  {agentFindings.length === 0 ? (
                    <div style={{ padding: '24px', textAlign: 'center', color: '#64748b' }}>
                      No threat findings recorded for this agent.
                    </div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                      <thead>
                        <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                          <th style={{ padding: '8px 12px' }}>Severity</th>
                          <th style={{ padding: '8px 12px' }}>Title</th>
                          <th style={{ padding: '8px 12px' }}>Rule ID</th>
                          <th style={{ padding: '8px 12px' }}>Confidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {agentFindings.map((f) => (
                          <tr key={f.finding_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                            <td style={{ padding: '8px 12px' }}>
                              <StatusBadge status={f.severity} type="severity" />
                            </td>
                            <td style={{ padding: '8px 12px', fontWeight: 600, color: '#0f172a' }}>
                              {f.title}
                            </td>
                            <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#64748b' }}>
                              {f.rule_id}
                            </td>
                            <td style={{ padding: '8px 12px', color: '#334155' }}>
                              {Math.round(f.confidence * 100)}%
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          )}
        </Modal>
      )}
    </div>
  );
};
