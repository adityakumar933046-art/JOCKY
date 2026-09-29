import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AuditLog } from '../types/api';

export const AuditDashboardPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');

  const loadAuditLogs = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getAuditLogs({
        action: actionFilter || undefined,
        actor_id: actorFilter || undefined,
        limit: 50,
      });
      setLogs(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [actionFilter, actorFilter]);

  const getResultBadge = (result: string) => {
    const isSuccess = result === 'SUCCESS';
    return (
      <span style={{
        padding: '0.2rem 0.55rem',
        borderRadius: '4px',
        fontSize: '0.75rem',
        fontWeight: 600,
        backgroundColor: isSuccess ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
        color: isSuccess ? '#86efac' : '#fca5a5',
        border: `1px solid ${isSuccess ? '#22c55e' : '#ef4444'}`,
      }}>
        {result}
      </span>
    );
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '1400px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, margin: 0 }}>Immutable Audit Ledger</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Append-only, cryptographically verifiable governance log of all security events and actions.
          </p>
        </div>
        <button
          onClick={loadAuditLogs}
          disabled={loading}
          style={{
            padding: '0.5rem 1rem',
            backgroundColor: '#1e293b',
            color: '#f8fafc',
            border: '1px solid #334155',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '0.875rem',
          }}
        >
          {loading ? 'Refreshing...' : 'Refresh Logs'}
        </button>
      </div>

      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid #ef4444',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '1.5rem',
          color: '#fca5a5',
        }}>
          {error}
        </div>
      )}

      {/* Filter Bar */}
      <div style={{
        display: 'flex',
        gap: '1rem',
        marginBottom: '1.5rem',
        backgroundColor: '#121722',
        border: '1px solid #1e293b',
        borderRadius: '8px',
        padding: '1rem',
      }}>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>Filter by Action</label>
          <input
            type="text"
            placeholder="e.g. USER_LOGIN_SUCCESS, AGENT_APPROVED, JOB_CREATED"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem 0.75rem',
              backgroundColor: '#0a0d14',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: 'white',
              fontSize: '0.875rem',
              boxSizing: 'border-box',
            }}
          />
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem' }}>Filter by Actor ID</label>
          <input
            type="text"
            placeholder="e.g. USR-ADMIN, AGT-WINDOWS-01"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            style={{
              width: '100%',
              padding: '0.5rem 0.75rem',
              backgroundColor: '#0a0d14',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: 'white',
              fontSize: '0.875rem',
              boxSizing: 'border-box',
            }}
          />
        </div>
      </div>

      {/* Logs Table */}
      <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ backgroundColor: '#0d1117', color: '#94a3b8', borderBottom: '1px solid #1e293b' }}>
                <th style={{ padding: '0.875rem 1.25rem' }}>Timestamp</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Actor</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Action</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Target Resource</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Result</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Source IP</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: '#64748b' }}>
                    No audit records matching filter criteria.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.audit_id} style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'block' }}>{log.actor_type}</span>
                      <span style={{ fontWeight: 600, color: '#f8fafc' }}>{log.actor_id}</span>
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', fontWeight: 600, color: '#38bdf8' }}>
                      {log.action}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'block' }}>{log.resource_type}</span>
                      <span style={{ color: '#cbd5e1' }}>{log.resource_id}</span>
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem' }}>
                      {getResultBadge(log.result)}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                      {log.ip_address || '—'}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#94a3b8', fontSize: '0.75rem', maxWidth: '240px' }}>
                      {log.details ? JSON.stringify(log.details) : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
