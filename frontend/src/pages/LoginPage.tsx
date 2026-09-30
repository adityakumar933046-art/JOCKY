import React, { useState } from 'react';
import { api } from '../services/api';

interface LoginPageProps {
  onLoginSuccess?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('AdminSecure2026!');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await api.login(username, password);
      if (onLoginSuccess) {
        onLoginSuccess();
      }
    } catch (err: any) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const setCredentials = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#0a0d14',
      fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      color: '#e2e8f0',
      padding: '1.5rem',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '440px',
        backgroundColor: '#121722',
        border: '1px solid #1e293b',
        borderRadius: '12px',
        padding: '2.5rem',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '48px',
            height: '48px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
            marginBottom: '1rem',
            boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)',
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, letterSpacing: '-0.025em' }}>JOCKY Forensic Platform</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', marginTop: '0.5rem' }}>Enterprise Security & Digital Forensics</p>
        </div>

        {error && (
          <div style={{
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid #ef4444',
            borderRadius: '8px',
            padding: '0.75rem 1rem',
            marginBottom: '1.5rem',
            color: '#fca5a5',
            fontSize: '0.875rem',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.5rem' }}>
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '0.75rem 1rem',
                backgroundColor: '#0a0d14',
                border: '1px solid #334155',
                borderRadius: '8px',
                color: 'white',
                fontSize: '0.9375rem',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.5rem' }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '0.75rem 1rem',
                backgroundColor: '#0a0d14',
                border: '1px solid #334155',
                borderRadius: '8px',
                color: 'white',
                fontSize: '0.9375rem',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.8125rem',
              backgroundColor: '#2563eb',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '0.9375rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.7 : 1,
              transition: 'background-color 0.15s ease',
            }}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div style={{ marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid #1e293b' }}>
          <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Quick Demo Accounts & Roles
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={() => setCredentials('admin', 'AdminSecure2026!')}
              style={{
                padding: '0.5rem',
                backgroundColor: '#1e293b',
                color: '#93c5fd',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              Super Admin
            </button>
            <button
              type="button"
              onClick={() => setCredentials('analyst', 'AnalystSecure2026!')}
              style={{
                padding: '0.5rem',
                backgroundColor: '#1e293b',
                color: '#6ee7b7',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              Security Analyst
            </button>
            <button
              type="button"
              onClick={() => setCredentials('signer', 'SignerSecure2026!')}
              style={{
                padding: '0.5rem',
                backgroundColor: '#1e293b',
                color: '#fcd34d',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              Forensic Signer
            </button>
            <button
              type="button"
              onClick={() => setCredentials('verifier', 'VerifierSecure2026!')}
              style={{
                padding: '0.5rem',
                backgroundColor: '#1e293b',
                color: '#c084fc',
                border: '1px solid #334155',
                borderRadius: '6px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              Evidence Verifier
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
