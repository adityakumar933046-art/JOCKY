import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Investigation } from '../types/api';
import { Header } from '../components/Header';
import { FileText, Download, ExternalLink, Printer } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await api.getInvestigations();
      setInvestigations(data);
      if (data.length > 0 && !selectedId) {
        setSelectedId(data[0].investigation_id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const currentReportHtmlUrl = selectedId ? api.getReportUrl(selectedId, 'html') : null;
  const currentReportJsonUrl = selectedId ? api.getReportUrl(selectedId, 'json') : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Forensic Reports & Incident Briefings"
        subtitle="Export court-ready HTML and JSON forensic reports with chain-of-custody and threat timelines"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 32px', overflow: 'hidden' }}>
        {/* Controls Bar */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
            backgroundColor: '#ffffff',
            padding: '12px 20px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
            flexShrink: 0,
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <label style={{ fontSize: '13px', fontWeight: 600, color: '#334155' }}>
              Select Investigation Case:
            </label>
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                minWidth: '320px',
                backgroundColor: '#ffffff',
                color: '#0f172a',
                fontWeight: 500,
              }}
            >
              {investigations.map((inv) => (
                <option key={inv.investigation_id} value={inv.investigation_id}>
                  {inv.title} ({inv.status})
                </option>
              ))}
            </select>
          </div>

          {selectedId && (
            <div style={{ display: 'flex', gap: '10px' }}>
              <a
                href={currentReportHtmlUrl || '#'}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  backgroundColor: '#ffffff',
                  border: '1px solid #cbd5e1',
                  color: '#2563eb',
                  fontSize: '13px',
                  fontWeight: 600,
                  textDecoration: 'none',
                }}
              >
                <ExternalLink size={14} />
                <span>Open in Tab / Print</span>
              </a>

              <a
                href={currentReportJsonUrl || '#'}
                download={`investigation_${selectedId}.json`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  backgroundColor: '#2563eb',
                  border: 'none',
                  color: '#ffffff',
                  fontSize: '13px',
                  fontWeight: 600,
                  textDecoration: 'none',
                }}
              >
                <Download size={14} />
                <span>Export JSON Package</span>
              </a>
            </div>
          )}
        </div>

        {/* Report Preview Container */}
        <div
          style={{
            flex: 1,
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {investigations.length === 0 ? (
            <div style={{ padding: '64px', textAlign: 'center', color: '#64748b' }}>
              <FileText size={42} color="#94a3b8" style={{ marginBottom: '16px' }} />
              <div style={{ fontWeight: 600, fontSize: '16px', color: '#0f172a' }}>
                No investigation reports generated yet
              </div>
              <div style={{ fontSize: '13px', marginTop: '6px' }}>
                Create an investigation case under <strong>Investigations</strong> to generate reports.
              </div>
            </div>
          ) : currentReportHtmlUrl ? (
            <iframe
              src={currentReportHtmlUrl}
              title="Forensic Investigation Report"
              style={{
                width: '100%',
                height: '100%',
                border: 'none',
              }}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
};
