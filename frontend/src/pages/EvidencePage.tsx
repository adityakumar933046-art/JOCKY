import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { EvidenceRecord, Agent } from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { Modal } from '../components/Modal';
import { FileSearch, Eye, Copy, Check } from 'lucide-react';

const OPERATIONS = [
  'SYSTEM_INFO',
  'PROCESSES',
  'PERSISTENCE',
  'DRIVERS',
  'NETWORK',
  'MEMORY',
  'SERVICES',
  'FILES',
];

export const EvidencePage: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [selectedOp, setSelectedOp] = useState<string>('');

  // Evidence Detail Modal
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null);
  const [copied, setCopied] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [evData, agData] = await Promise.all([
        api.getEvidence({
          agent_id: selectedAgent || undefined,
          operation: selectedOp || undefined,
        }),
        api.getAgents(),
      ]);
      setEvidenceList(evData);
      setAgents(agData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedAgent, selectedOp]);

  const handleCopyJson = () => {
    if (selectedEvidence) {
      navigator.clipboard.writeText(JSON.stringify(selectedEvidence.data, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Forensic Evidence Store"
        subtitle="Centralized, immutable evidence records collected from endpoints"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        {/* Filter Bar */}
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
            value={selectedOp}
            onChange={(e) => setSelectedOp(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px',
              backgroundColor: '#ffffff',
              color: '#334155',
            }}
          >
            <option value="">All Forensic Operations</option>
            {OPERATIONS.map((op) => (
              <option key={op} value={op}>
                {op}
              </option>
            ))}
          </select>

          <div style={{ fontSize: '13px', color: '#64748b', marginLeft: 'auto' }}>
            Showing <strong>{evidenceList.length}</strong> evidence records
          </div>
        </div>

        {/* Evidence Table */}
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
          }}
        >
          {evidenceList.length === 0 ? (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <FileSearch size={36} color="#94a3b8" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: '#0f172a' }}>No evidence records found</div>
              <div style={{ fontSize: '13px', marginTop: '4px' }}>
                Run forensic collection jobs on managed systems to populate the evidence store.
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Operation</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>System Hostname</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Evidence ID</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {evidenceList.map((ev) => (
                  <tr
                    key={ev.evidence_id}
                    style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                    onClick={() => setSelectedEvidence(ev)}
                  >
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: '#0f172a' }}>
                      {ev.operation}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge status={ev.collection_status} />
                    </td>
                    <td style={{ padding: '12px 16px', color: '#334155' }}>
                      {ev.hostname || ev.agent_id.substring(0, 10)}
                    </td>
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: '#64748b' }}>
                      {ev.evidence_id}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b' }}>
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvidence(ev);
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

      {/* Evidence Viewer Modal */}
      {selectedEvidence && (
        <Modal
          isOpen={!!selectedEvidence}
          onClose={() => setSelectedEvidence(null)}
          title={`Evidence Record: ${selectedEvidence.operation} (${selectedEvidence.evidence_id.substring(0, 8)})`}
          maxWidth="850px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '12px',
                backgroundColor: '#f8fafc',
                padding: '12px 16px',
                borderRadius: '6px',
                border: '1px solid #e2e8f0',
                fontSize: '12px',
              }}
            >
              <div>
                <span style={{ color: '#64748b' }}>Operation:</span>{' '}
                <strong>{selectedEvidence.operation}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Hostname:</span>{' '}
                <strong>{selectedEvidence.hostname}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Status:</span>{' '}
                <strong>{selectedEvidence.collection_status}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Evidence ID:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{selectedEvidence.evidence_id}</span>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Agent ID:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{selectedEvidence.agent_id}</span>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Timestamp:</span>{' '}
                <span>{new Date(selectedEvidence.timestamp).toLocaleString()}</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#0f172a' }}>
                Forensic Payload Data
              </div>
              <button
                onClick={handleCopyJson}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: '4px 8px',
                  backgroundColor: '#ffffff',
                  border: '1px solid #cbd5e1',
                  borderRadius: '4px',
                  fontSize: '12px',
                  color: '#334155',
                  cursor: 'pointer',
                }}
              >
                {copied ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
              </button>
            </div>

            <pre
              style={{
                backgroundColor: '#0f172a',
                color: '#f8fafc',
                padding: '16px',
                borderRadius: '6px',
                fontSize: '12px',
                lineHeight: '1.5',
                overflowX: 'auto',
                maxHeight: '400px',
                fontFamily: 'Consolas, "Fira Code", monospace',
              }}
            >
              {JSON.stringify(selectedEvidence.data, null, 2)}
            </pre>
          </div>
        </Modal>
      )}
    </div>
  );
};
