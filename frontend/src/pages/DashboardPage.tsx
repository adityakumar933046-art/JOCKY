import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Agent, Job, Finding, EvidenceRecord } from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { PageId } from '../components/Sidebar';
import {
  Server,
  PlaySquare,
  ShieldAlert,
  FileSearch,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';

interface Props {
  onNavigate: (page: PageId) => void;
}

export const DashboardPage: React.FC<Props> = ({ onNavigate }) => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [agRes, jbRes, fnRes, evRes] = await Promise.all([
        api.getAgents(),
        api.getJobs(),
        api.getFindings(),
        api.getEvidence(),
      ]);
      setAgents(agRes);
      setJobs(jbRes);
      setFindings(fnRes);
      setEvidence(evRes);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to central server');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000); // auto-refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const onlineAgents = agents.filter((a) => a.status === 'ONLINE').length;
  const offlineAgents = agents.filter((a) => a.status === 'OFFLINE').length;
  const activeJobs = jobs.filter(
    (j) => j.status === 'PENDING' || j.status === 'ASSIGNED' || j.status === 'RUNNING'
  ).length;

  const severityCounts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
    INFO: findings.filter((f) => f.severity === 'INFO').length,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Forensic Operations Overview"
        subtitle="Central multi-system triage, evidence collection, and threat detection"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        {error && (
          <div
            style={{
              padding: '12px 16px',
              backgroundColor: '#fef2f2',
              border: '1px solid #fecaca',
              borderRadius: '6px',
              color: '#991b1b',
              marginBottom: '24px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        {/* Metric Cards Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '20px',
            marginBottom: '32px',
          }}
        >
          {/* Card 1: Systems */}
          <div
            onClick={() => onNavigate('systems')}
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              padding: '20px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
              transition: 'transform 0.1s ease',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#64748b' }}>TOTAL SYSTEMS</span>
              <Server size={20} color="#2563eb" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#0f172a' }}>{agents.length}</div>
            <div style={{ fontSize: '12px', marginTop: '6px', color: '#64748b', display: 'flex', gap: '8px' }}>
              <span style={{ color: '#047857', fontWeight: 600 }}>{onlineAgents} online</span>
              <span>•</span>
              <span style={{ color: '#991b1b', fontWeight: 600 }}>{offlineAgents} offline</span>
            </div>
          </div>

          {/* Card 2: Active Jobs */}
          <div
            onClick={() => onNavigate('jobs')}
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              padding: '20px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#64748b' }}>ACTIVE JOBS</span>
              <PlaySquare size={20} color="#0284c7" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#0f172a' }}>{activeJobs}</div>
            <div style={{ fontSize: '12px', marginTop: '6px', color: '#64748b' }}>
              <span>{jobs.length} total executed</span>
            </div>
          </div>

          {/* Card 3: Evidence Records */}
          <div
            onClick={() => onNavigate('evidence')}
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              padding: '20px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#64748b' }}>EVIDENCE STORED</span>
              <FileSearch size={20} color="#8b5cf6" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#0f172a' }}>{evidence.length}</div>
            <div style={{ fontSize: '12px', marginTop: '6px', color: '#64748b' }}>
              <span>Structured forensic artifacts</span>
            </div>
          </div>

          {/* Card 4: Findings */}
          <div
            onClick={() => onNavigate('findings')}
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              padding: '20px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#64748b' }}>TOTAL THREATS</span>
              <ShieldAlert size={20} color="#ef4444" />
            </div>
            <div style={{ fontSize: '28px', fontWeight: 800, color: '#0f172a' }}>{findings.length}</div>
            <div style={{ fontSize: '12px', marginTop: '6px', color: '#64748b' }}>
              <span style={{ color: '#dc2626', fontWeight: 600 }}>
                {severityCounts.CRITICAL + severityCounts.HIGH} Critical / High
              </span>
            </div>
          </div>
        </div>

        {/* Threat Distribution Summary */}
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            padding: '20px 24px',
            border: '1px solid #e2e8f0',
            marginBottom: '32px',
          }}
        >
          <h3 style={{ margin: '0 0 16px 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
            Threat Severity Distribution
          </h3>
          <div
            style={{
              display: 'flex',
              gap: '16px',
              flexWrap: 'wrap',
            }}
          >
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
              <div
                key={sev}
                onClick={() => onNavigate('findings')}
                style={{
                  flex: 1,
                  minWidth: '140px',
                  backgroundColor: '#f8fafc',
                  padding: '14px 16px',
                  borderRadius: '6px',
                  border: '1px solid #e2e8f0',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <StatusBadge status={sev} type="severity" />
                  <span style={{ fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                    {severityCounts[sev]}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Two-Column Tables Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '24px' }}>
          {/* Recent Threat Findings */}
          <div
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              overflow: 'hidden',
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
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Recent Threat Findings
              </h3>
              <button
                onClick={() => onNavigate('findings')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#2563eb',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer',
                }}
              >
                <span>View all</span>
                <ArrowRight size={14} />
              </button>
            </div>
            <div>
              {findings.length === 0 ? (
                <div style={{ padding: '32px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
                  <CheckCircle2 size={32} color="#10b981" style={{ marginBottom: '8px' }} />
                  <div>No threat findings recorded yet. Execute forensic jobs with detection enabled.</div>
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Severity</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Title</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Rule</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Agent</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.slice(0, 5).map((f) => (
                      <tr
                        key={f.finding_id}
                        style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                        onClick={() => onNavigate('findings')}
                      >
                        <td style={{ padding: '10px 16px' }}>
                          <StatusBadge status={f.severity} type="severity" />
                        </td>
                        <td style={{ padding: '10px 16px', fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                        <td style={{ padding: '10px 16px', color: '#64748b', fontFamily: 'monospace' }}>
                          {f.rule_id}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>
                          {f.agent_id.substring(0, 12)}...
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Recent Jobs */}
          <div
            style={{
              backgroundColor: '#ffffff',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              overflow: 'hidden',
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
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Recent Forensic Jobs
              </h3>
              <button
                onClick={() => onNavigate('jobs')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#2563eb',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer',
                }}
              >
                <span>View all</span>
                <ArrowRight size={14} />
              </button>
            </div>
            <div>
              {jobs.length === 0 ? (
                <div style={{ padding: '32px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
                  No forensic jobs have been dispatched yet.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Status</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Job Name</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Agent</th>
                      <th style={{ padding: '10px 16px', color: '#64748b', fontWeight: 600 }}>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.slice(0, 5).map((j) => (
                      <tr
                        key={j.job_id}
                        style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                        onClick={() => onNavigate('jobs')}
                      >
                        <td style={{ padding: '10px 16px' }}>
                          <StatusBadge status={j.status} type="job" />
                        </td>
                        <td style={{ padding: '10px 16px', fontWeight: 600, color: '#0f172a' }}>{j.name}</td>
                        <td style={{ padding: '10px 16px', color: '#64748b', fontFamily: 'monospace', fontSize: '12px' }}>
                          {j.agent_id.substring(0, 12)}...
                        </td>
                        <td style={{ padding: '10px 16px', color: '#64748b' }}>
                          {new Date(j.created_at).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
