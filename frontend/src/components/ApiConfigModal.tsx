import React, { useState } from 'react';
import { getApiBaseUrl, setApiBaseUrl, api } from '../services/api';
import { Globe, CheckCircle2, XCircle, RefreshCw, X, Shield } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onConnected?: () => void;
}

export const ApiConfigModal: React.FC<Props> = ({ isOpen, onClose, onConnected }) => {
  const currentBase = getApiBaseUrl();
  const [inputUrl, setInputUrl] = useState(
    currentBase === '/api/v1' ? '' : currentBase.replace(/\/api\/v1$/, '')
  );
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    tested: boolean;
    ok: boolean;
    message: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    const target = inputUrl.trim() || '/api/v1';
    const result = await api.testConnection(target);
    setTestResult({
      tested: true,
      ok: result.ok,
      message: result.message || (result.ok ? 'Connection successful!' : 'Connection failed.'),
    });
    setTesting(false);
  };

  const handleSave = () => {
    const target = inputUrl.trim();
    if (!target) {
      setApiBaseUrl(null);
    } else {
      setApiBaseUrl(target);
    }
    if (onConnected) onConnected();
    onClose();
    window.location.reload();
  };

  const handlePreset = (url: string) => {
    setInputUrl(url);
    setTestResult(null);
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          width: '100%',
          maxWidth: '540px',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 8px 10px -6px rgba(0, 0, 0, 0.2)',
          overflow: 'hidden',
          border: '1px solid #e2e8f0',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid #f1f5f9',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backgroundColor: '#f8fafc',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                backgroundColor: '#2563eb',
                borderRadius: '8px',
                padding: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Globe size={18} color="#ffffff" />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#0f172a' }}>
                Backend API Connection
              </h2>
              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: '#64748b' }}>
                Connect this Vercel dashboard to your Render backend
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '4px',
              borderRadius: '4px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '24px' }}>
          <div style={{ marginBottom: '16px' }}>
            <label
              style={{
                display: 'block',
                fontSize: '13px',
                fontWeight: 600,
                color: '#334155',
                marginBottom: '6px',
              }}
            >
              Backend API URL
            </label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  setTestResult(null);
                }}
                placeholder="https://jocky-backend.onrender.com"
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px',
                  color: '#0f172a',
                  outline: 'none',
                  backgroundColor: '#ffffff',
                }}
              />
              <button
                type="button"
                onClick={handleTest}
                disabled={testing}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 16px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  backgroundColor: '#f1f5f9',
                  color: '#334155',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: testing ? 'not-allowed' : 'pointer',
                }}
              >
                {testing && <RefreshCw size={14} className="animate-spin" />}
                <span>{testing ? 'Testing...' : 'Test'}</span>
              </button>
            </div>
            <div style={{ marginTop: '6px', fontSize: '11px', color: '#64748b' }}>
              Active endpoint: <code>{currentBase}</code>
            </div>
          </div>

          {/* Test Status Banner */}
          {testResult && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                marginBottom: '16px',
                backgroundColor: testResult.ok ? '#f0fdf4' : '#fef2f2',
                border: `1px solid ${testResult.ok ? '#bbf7d0' : '#fecaca'}`,
                color: testResult.ok ? '#15803d' : '#b91c1c',
              }}
            >
              {testResult.ok ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
              <span>{testResult.message}</span>
            </div>
          )}

          {/* Quick Connect Presets */}
          <div style={{ marginBottom: '20px' }}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '8px' }}>
              Quick Presets:
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <button
                type="button"
                onClick={() => handlePreset('https://potential-merchants-jelsoft-plastics.trycloudflare.com')}
                style={{
                  padding: '8px 12px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  textAlign: 'left',
                  fontSize: '12px',
                  color: '#1e293b',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span style={{ fontWeight: 500 }}>Live Cloudflare Tunnel</span>
                <span style={{ fontSize: '11px', color: '#2563eb' }}>Select</span>
              </button>

              <button
                type="button"
                onClick={() => handlePreset('http://127.0.0.1:8000')}
                style={{
                  padding: '8px 12px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  textAlign: 'left',
                  fontSize: '12px',
                  color: '#1e293b',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span style={{ fontWeight: 500 }}>Localhost Development (http://127.0.0.1:8000)</span>
                <span style={{ fontSize: '11px', color: '#2563eb' }}>Select</span>
              </button>

              <button
                type="button"
                onClick={() => handlePreset('')}
                style={{
                  padding: '8px 12px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  textAlign: 'left',
                  fontSize: '12px',
                  color: '#64748b',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span>Reset to Default (/api/v1 Same-Origin)</span>
                <span style={{ fontSize: '11px', color: '#64748b' }}>Reset</span>
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '16px 24px',
            backgroundColor: '#f8fafc',
            borderTop: '1px solid #f1f5f9',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '10px',
          }}
        >
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#475569',
              fontSize: '13px',
              fontWeight: 500,
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            style={{
              padding: '8px 20px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Save & Connect
          </button>
        </div>
      </div>
    </div>
  );
};
