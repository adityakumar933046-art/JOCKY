import React from 'react';
import {
  LayoutDashboard,
  Server,
  PlaySquare,
  FileSearch,
  ShieldAlert,
  FolderGit2,
  FileText,
  Shield,
  Share2,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'systems'
  | 'jobs'
  | 'evidence'
  | 'findings'
  | 'correlation'
  | 'investigations'
  | 'reports'
  | 'security'
  | 'audit';

interface Props {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
}

export const Sidebar: React.FC<Props> = ({ currentPage, onNavigate }) => {
  const navItems: Array<{ id: PageId; label: string; icon: React.ReactNode }> = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    { id: 'systems', label: 'Systems & Trust', icon: <Server size={18} /> },
    { id: 'jobs', label: 'Jobs', icon: <PlaySquare size={18} /> },
    { id: 'evidence', label: 'Evidence', icon: <FileSearch size={18} /> },
    { id: 'findings', label: 'Findings', icon: <ShieldAlert size={18} /> },
    { id: 'correlation', label: 'Correlation', icon: <Share2 size={18} /> },
    { id: 'investigations', label: 'Investigations', icon: <FolderGit2 size={18} /> },
    { id: 'reports', label: 'Reports', icon: <FileText size={18} /> },
    { id: 'security', label: 'Security Ops', icon: <Shield size={18} /> },
    { id: 'audit', label: 'Audit Ledger', icon: <FileSearch size={18} /> },
  ];

  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: '#0f172a',
        color: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        boxSizing: 'border-box',
        borderRight: '1px solid #1e293b',
        flexShrink: 0,
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '24px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          borderBottom: '1px solid #1e293b',
        }}
      >
        <div
          style={{
            backgroundColor: '#2563eb',
            borderRadius: '6px',
            padding: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Shield size={22} color="#ffffff" />
        </div>
        <div>
          <div style={{ fontSize: '18px', fontWeight: 800, letterSpacing: '0.05em', color: '#ffffff' }}>
            JOCKY
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Forensics Platform
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ padding: '16px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {navItems.map((item) => {
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 14px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? '#ffffff' : '#94a3b8',
                backgroundColor: isActive ? '#2563eb' : 'transparent',
                border: 'none',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = '#1e293b';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              {item.icon}
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid #1e293b', fontSize: '12px', color: '#64748b' }}>
        <div>JOCKY Platform v1.0.0</div>
        <div>Analyst Mode: Active</div>
      </div>
    </aside>
  );
};
