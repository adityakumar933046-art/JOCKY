import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Finding, Agent } from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { Modal } from '../components/Modal';
import { ShieldAlert, Eye, AlertOctagon, CheckCircle2 } from 'lucide-react';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CATEGORIES = ['PROCESS', 'PERSISTENCE', 'DRIVER', 'NETWORK', 'MEMORY', 'SERVICE', 'FILE'];

export const FindingsPage: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('');

  // Finding Detail Modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [fnData, agData] = await Promise.all([
        api.getFindings({
          agent_id: selectedAgent || undefined,
          severity: selectedSeverity || undefined,
          category: selectedCategory || undefined,
        }),
        api.getAgents(),
      ]);
      setFindings(fnData);
      setAgents(agData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedAgent, selectedSeverity, selectedCategory]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Threat Findings"
        subtitle="Suspicious artifacts and indicators of compromise flagged by the Step 3 Threat Engine"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        {/* Filters Bar */}
        <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', alignItems: 'center' }}>
          <select
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              backgroundColor: '#ffffff',
              color: '#334155',
            }}
          >
            <option value="">All Systems</option>
            {agents.map((ag) => (
              <option key={ag.agent_id} value={ag.agent_id}>
                {ag.hostname} ({ag.operating_system})
              </option>
            ))}
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              backgroundColor: '#ffffff',
              color: '#334155',
            }}
          >
            <option value="">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              backgroundColor: '#ffffff',
              color: '#334155',
            }}
          >
            <option value="">All Categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <div style={{ fontSize: '13px', color: '#64748b', marginLeft: 'auto' }}>
            Showing <strong>{findings.length}</strong> findings
          </div>
        </div>

        {/* Findings Table */}
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
          }}
        >
          {findings.length === 0 ? (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <CheckCircle2 size={36} color="#10b981" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: '#0f172a' }}>
                No threat findings detected
              </div>
              <div style={{ fontSize: '13px', marginTop: '4px' }}>
                All executed forensic scans on target endpoints are clean, or matching filter criteria returned zero results.
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Severity</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Title</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Category</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Rule ID</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Affected Object</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Confidence</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.finding_id}
                    style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                    onClick={() => setSelectedFinding(f)}
                  >
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge status={f.severity} type="severity" />
                    </td>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                    <td style={{ padding: '12px 16px', color: '#334155', textTransform: 'capitalize' }}>
                      {f.category}
                    </td>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#64748b' }}>
                      {f.rule_id}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#334155' }}>
                      {f.affected_object || '—'}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#334155' }}>
                      {Math.round(f.confidence * 100)}%
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b' }}>
                      {new Date(f.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        style={{
                          padding: '4px 8px',
                          backgroundColor: '#f1f5f9',
                          border: '1px solid #cbd5e1',
                          borderRadius: '4px',
                          color: '#2563eb',
                          fontSize: '12px',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <Modal
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          title={`Threat Finding: ${selectedFinding.title}`}
          maxWidth="750px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '12px',
                backgroundColor: '#f8fafc',
                padding: '16px',
                borderRadius: '6px',
                border: '1px solid #e2e8f0',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>SEVERITY</div>
                <div style={{ marginTop: '4px' }}>
                  <StatusBadge status={selectedFinding.severity} type="severity" />
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>CATEGORY</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#0f172a', marginTop: '4px', textTransform: 'capitalize' }}>
                  {selectedFinding.category}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>CONFIDENCE</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#0f172a', marginTop: '4px' }}>
                  {Math.round(selectedFinding.confidence * 100)}%
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>RULE ID</div>
                <div style={{ fontSize: '12px', fontFamily: 'monospace', color: '#334155', marginTop: '4px' }}>
                  {selectedFinding.rule_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>AFFECTED OBJECT</div>
                <div style={{ fontSize: '12px', color: '#334155', marginTop: '4px' }}>
                  {selectedFinding.affected_object || 'N/A'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>DETECTED AT</div>
                <div style={{ fontSize: '12px', color: '#334155', marginTop: '4px' }}>
                  {new Date(selectedFinding.timestamp).toLocaleString()}
                </div>
              </div>
            </div>

            {selectedFinding.description && (
              <div>
                <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '4px' }}>
                  DESCRIPTION
                </div>
                <div style={{ fontSize: '13px', color: '#334155', lineHeight: '1.5' }}>
                  {selectedFinding.description}
                </div>
              </div>
            )}

            {selectedFinding.recommendation && (
              <div
                style={{
                  padding: '12px 16px',
                  backgroundColor: '#f0fdf4',
                  border: '1px solid #bbf7d0',
                  borderRadius: '6px',
                }}
              >
                <div style={{ fontSize: '12px', fontWeight: 600, color: '#166534', marginBottom: '2px' }}>
                  INVESTIGATOR RECOMMENDATION
                </div>
                <div style={{ fontSize: '13px', color: '#15803d' }}>
                  {selectedFinding.recommendation}
                </div>
              </div>
            )}

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
                INDICATORS & CONTEXT
              </div>
              <pre
                style={{
                  backgroundColor: '#0f172a',
                  color: '#f8fafc',
                  padding: '14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  lineHeight: '1.4',
                  overflowX: 'auto',
                  fontFamily: 'Consolas, "Fira Code", monospace',
                }}
              >
                {JSON.stringify(selectedFinding.indicators, null, 2)}
              </pre>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
