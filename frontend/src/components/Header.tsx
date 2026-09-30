import React, { useState } from 'react';
import { RefreshCw, ShieldCheck, Search, Globe, LogOut } from 'lucide-react';
import { getApiBaseUrl } from '../services/api';
import { ApiConfigModal } from './ApiConfigModal';

interface Props {
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  loading?: boolean;
  action?: React.ReactNode;
  onSearchClick?: () => void;
  onLogout?: () => void;
}

export const Header: React.FC<Props> = ({
  title,
  subtitle,
  onRefresh,
  loading = false,
  action,
  onSearchClick,
  onLogout,
}) => {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const currentBase = getApiBaseUrl();
  const isCustomUrl = currentBase !== '/api/v1';
  const displayLabel = isCustomUrl
    ? currentBase.replace(/^https?:\/\//, '').replace(/\/api\/v1$/, '')
    : 'Local / Same-Origin';

  return (
    <header
      style={{
        backgroundColor: '#ffffff',
        borderBottom: '1px solid #e2e8f0',
        padding: '16px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
        flexWrap: 'wrap',
        gap: '12px',
      }}
    >
      <div>
        <h1 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: '#0f172a' }}>{title}</h1>
        {subtitle && <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>{subtitle}</p>}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        {onSearchClick && (
          <button
            onClick={onSearchClick}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#f8fafc',
              border: '1px solid #cbd5e1',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              color: '#475569',
              cursor: 'pointer',
              fontWeight: 500,
            }}
          >
            <Search size={14} />
            <span>Search IOCs / Artifacts (Ctrl+K)</span>
          </button>
        )}

        {action}

        {/* Backend API Configuration Button */}
        <button
          type="button"
          onClick={() => setIsConfigOpen(true)}
          title={`Backend API Endpoint: ${currentBase}\nClick to configure or test connection`}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            backgroundColor: isCustomUrl ? '#eff6ff' : '#f8fafc',
            border: `1px solid ${isCustomUrl ? '#bfdbfe' : '#cbd5e1'}`,
            padding: '6px 12px',
            borderRadius: '20px',
            fontSize: '12px',
            color: isCustomUrl ? '#1d4ed8' : '#475569',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <Globe size={14} color={isCustomUrl ? '#2563eb' : '#64748b'} />
          <span>API: {displayLabel.length > 25 ? `${displayLabel.slice(0, 23)}...` : displayLabel}</span>
        </button>

        {/* Analyst Mode Badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            backgroundColor: '#f1f5f9',
            padding: '6px 12px',
            borderRadius: '20px',
            fontSize: '12px',
            color: '#334155',
            fontWeight: 500,
          }}
        >
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: '#10b981',
              display: 'inline-block',
            }}
          />
          <ShieldCheck size={14} color="#2563eb" />
          <span>Analyst Auth Active</span>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#334155',
              fontSize: '13px',
              fontWeight: 500,
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.15s ease',
            }}
          >
            <RefreshCw
              size={14}
              style={{
                animation: loading ? 'spin 1s linear infinite' : 'none',
              }}
            />
            <span>Refresh</span>
          </button>
        )}

        {onLogout && (
          <button
            type="button"
            onClick={onLogout}
            title="Log out and return to Gateway Portal"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 12px',
              borderRadius: '6px',
              border: '1px solid #fecaca',
              backgroundColor: '#fef2f2',
              color: '#dc2626',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = '#fee2e2';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = '#fef2f2';
            }}
          >
            <LogOut size={14} />
            <span>Logout</span>
          </button>
        )}
      </div>

      <ApiConfigModal
        isOpen={isConfigOpen}
        onClose={() => setIsConfigOpen(false)}
        onConnected={onRefresh}
      />
    </header>
  );
};
