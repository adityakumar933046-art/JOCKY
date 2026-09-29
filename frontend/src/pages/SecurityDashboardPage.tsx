import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SecurityMetrics, SecurityEvent } from '../types/api';

export const SecurityDashboardPage: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [m, e] = await Promise.all([
        api.getSecurityMetrics(),
        api.getSecurityEvents({ limit: 20 }),
      ]);
      setMetrics(m);
      setEvents(e);
    } catch (err: any) {
      setError(err.message || 'Failed to load security dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityBadge = (severity: string) => {
    const s = severity.toUpperCase();
    const colors: Record<string, { bg: string; text: string; border: string }> = {
      CRITICAL: { bg: 'rgba(239, 68, 68, 0.2)', text: '#fca5a5', border: '#ef4444' },
      HIGH: { bg: 'rgba(249, 115, 22, 0.2)', text: '#fdba74', border: '#f97316' },
      MEDIUM: { bg: 'rgba(234, 179, 8, 0.2)', text: '#fde047', border: '#eab308' },
      LOW: { bg: 'rgba(59, 130, 246, 0.2)', text: '#93c5fd', border: '#3b82f6' },
    };
    const c = colors[s] || colors.LOW;
    return (
      <span style={{
        padding: '0.2rem 0.55rem',
        borderRadius: '4px',
        fontSize: '0.75rem',
        fontWeight: 600,
        backgroundColor: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
      }}>
        {s}
      </span>
    );
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '1400px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, margin: 0 }}>Security Operations Center</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Real-time security telemetry, authentication monitoring, and agent governance.
          </p>
        </div>
        <button
          onClick={loadData}
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
          {loading ? 'Refreshing...' : 'Refresh Telemetry'}
        </button>
      </div>

      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid #ef4444',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '2rem',
          color: '#fca5a5',
        }}>
          {error}
        </div>
      )}

      {/* Metric Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '1.25rem',
        marginBottom: '2rem',
      }}>
        <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 600, textTransform: 'uppercase' }}>Active Analysts</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#38bdf8', marginTop: '0.5rem' }}>
            {metrics ? `${metrics.active_users} / ${metrics.total_users}` : '—'}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Authenticated Users</div>
        </div>

        <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 600, textTransform: 'uppercase' }}>Locked Accounts</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: (metrics?.locked_accounts || 0) > 0 ? '#ef4444' : '#22c55e', marginTop: '0.5rem' }}>
            {metrics?.locked_accounts ?? '—'}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Brute-force Lockouts</div>
        </div>

        <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 600, textTransform: 'uppercase' }}>Integrity Violations</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: (metrics?.integrity_violations || 0) > 0 ? '#ef4444' : '#22c55e', marginTop: '0.5rem' }}>
            {metrics?.integrity_violations ?? '0'}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Evidence Hash Mismatches</div>
        </div>

        <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8125rem', fontWeight: 600, textTransform: 'uppercase' }}>Security Events (24h)</div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: '#f59e0b', marginTop: '0.5rem' }}>
            {metrics?.security_events_last_24h ?? '—'}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>Failed Logins: {metrics?.failed_logins_last_24h ?? 0}</div>
        </div>
      </div>

      {/* Agent Trust Breakdown Card */}
      <div style={{
        backgroundColor: '#121722',
        border: '1px solid #1e293b',
        borderRadius: '10px',
        padding: '1.5rem',
        marginBottom: '2rem',
      }}>
        <h2 style={{ fontSize: '1.125rem', fontWeight: 600, margin: '0 0 1rem 0' }}>Agent Trust State Distribution</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
          <div style={{ padding: '1rem', backgroundColor: '#0f172a', borderRadius: '8px', borderLeft: '4px solid #22c55e' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Authorized</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#22c55e', marginTop: '0.25rem' }}>
              {metrics?.agents_by_trust?.AUTHORIZED || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Active & Trusted</div>
          </div>

          <div style={{ padding: '1rem', backgroundColor: '#0f172a', borderRadius: '8px', borderLeft: '4px solid #eab308' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Pending Review</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#eab308', marginTop: '0.25rem' }}>
              {metrics?.agents_by_trust?.PENDING || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Awaiting Approval</div>
          </div>

          <div style={{ padding: '1rem', backgroundColor: '#0f172a', borderRadius: '8px', borderLeft: '4px solid #f97316' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Suspended</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f97316', marginTop: '0.25rem' }}>
              {metrics?.agents_by_trust?.SUSPENDED || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Execution Blocked</div>
          </div>

          <div style={{ padding: '1rem', backgroundColor: '#0f172a', borderRadius: '8px', borderLeft: '4px solid #ef4444' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>Revoked</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ef4444', marginTop: '0.25rem' }}>
              {metrics?.agents_by_trust?.REVOKED || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Permanently Banned</div>
          </div>
        </div>
      </div>

      {/* Recent Security Incidents Table */}
      <div style={{ backgroundColor: '#121722', border: '1px solid #1e293b', borderRadius: '10px', overflow: 'hidden' }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '1.125rem', fontWeight: 600, margin: 0 }}>Recent Security Incidents & Anomalies</h2>
          <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>Showing latest {events.length} incidents</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ backgroundColor: '#0d1117', color: '#94a3b8', borderBottom: '1px solid #1e293b' }}>
                <th style={{ padding: '0.875rem 1.25rem' }}>Timestamp</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Severity</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Event Type</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Description</th>
                <th style={{ padding: '0.875rem 1.25rem' }}>Source IP</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
                    No security events recorded. Platform is secure.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.event_id} style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem' }}>
                      {getSeverityBadge(ev.severity)}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', fontWeight: 600, color: '#f8fafc' }}>
                      {ev.event_type}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#cbd5e1' }}>
                      {ev.description}
                    </td>
                    <td style={{ padding: '0.875rem 1.25rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                      {ev.source_ip || 'Internal'}
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
