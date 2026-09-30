import React from 'react';
import {
  LayoutDashboard,
  Server,
  Terminal,
  FileSearch,
  ShieldAlert,
  Hash,
  Share2,
  Clock,
  FolderGit2,
  FileText,
  FileSpreadsheet,
  Settings,
  Shield,
  LogOut,
  UserCheck,
  Lock,
} from 'lucide-react';
import { removeAuthToken } from '../services/api';

export type PageId =
  | 'login'
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
    { id: 'dashboard', label: 'Command Center', icon: <LayoutDashboard size={16} /> },
    { id: 'systems', label: 'Monitored Systems', icon: <Server size={16} /> },
    { id: 'jobs', label: 'Forensic Scripts', icon: <Terminal size={16} /> },
    { id: 'evidence', label: 'Evidence Vault', icon: <FileSearch size={16} /> },
    { id: 'findings', label: 'Threat Incidents', icon: <ShieldAlert size={16} /> },
    { id: 'correlation', label: 'Cross Correlation', icon: <Share2 size={16} /> },
    { id: 'investigations', label: 'Investigations', icon: <FolderGit2 size={16} /> },
    { id: 'reports', label: 'Forensic Reports', icon: <FileText size={16} /> },
    { id: 'audit', label: 'Audit Ledger', icon: <FileSpreadsheet size={16} /> },
    { id: 'security', label: 'Security & Settings', icon: <Settings size={16} /> },
  ];

  let currentUsername = 'analyst';
  let currentRole = 'Security Analyst';
  let currentOrg = 'JOCKY Forensics Core (Default)';
  try {
    const rawUser = localStorage.getItem('jocky_user');
    if (rawUser) {
      const u = JSON.parse(rawUser);
      if (u.username) currentUsername = u.username;
      if (u.role) {
        currentRole = u.role.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c: string) => c.toUpperCase());
      }
      if (u.organization_id) {
        currentOrg = u.organization_id.replace(/^org-/, 'ORG ').toUpperCase();
      }
    }
  } catch {}

  const handleLogout = () => {
    removeAuthToken();
    onNavigate('login');
  };

  return (
    <aside
      style={{
        width: '235px',
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
          padding: '16px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          borderBottom: '1px solid #1e293b',
        }}
      >
        <div
          style={{
            backgroundColor: '#1d4ed8',
            borderRadius: '6px',
            padding: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 2px 6px rgba(29, 78, 216, 0.4)',
          }}
        >
          <Shield size={20} color="#ffffff" />
        </div>
        <div>
          <div style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '0.08em', color: '#ffffff' }}>
            JOCKY
          </div>
          <div style={{ fontSize: '9px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
            FORENSIC ANALYSIS PLATFORM
          </div>
        </div>
      </div>

      {/* Current Role Box (Q-SHIELD reference aesthetic) */}
      <div
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid #1e293b',
          backgroundColor: '#0b1120',
        }}
      >
        <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          CURRENT ROLE
        </div>
        <div style={{ fontSize: '12px', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.04em', marginTop: '2px', textTransform: 'uppercase' }}>
          {currentRole}
        </div>
      </div>

      {/* Navigation Links */}
      <nav
        style={{
          padding: '12px 8px',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: '2px',
          overflowY: 'auto',
        }}
      >
        {navItems.map((item) => {
          const isActive = currentPage === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '8px 12px',
                borderRadius: '5px',
                fontSize: '12px',
                fontWeight: isActive ? 700 : 500,
                letterSpacing: '0.02em',
                color: isActive ? '#ffffff' : '#94a3b8',
                backgroundColor: isActive ? '#1d4ed8' : 'transparent',
                border: 'none',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.12s ease',
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = '#1e293b';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <span style={{ color: isActive ? '#ffffff' : '#64748b' }}>{item.icon}</span>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Bottom User Info & Security Status */}
      <div
        style={{
          padding: '14px 14px',
          borderTop: '1px solid #1e293b',
          fontSize: '11px',
          color: '#94a3b8',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          backgroundColor: '#0b1120',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div
            style={{
              width: '26px',
              height: '26px',
              borderRadius: '4px',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#38bdf8',
            }}
          >
            <UserCheck size={14} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 700, color: '#f1f5f9', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {currentUsername}
            </div>
            <div style={{ fontSize: '10px', color: '#64748b' }}>{currentRole}</div>
          </div>
        </div>

        <div style={{ fontSize: '10px', color: '#64748b', display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div>
            <span style={{ color: '#475569' }}>Organization: </span>
            <strong style={{ color: '#94a3b8' }}>{currentOrg}</strong>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#10b981', fontWeight: 600 }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10b981', display: 'inline-block' }} />
            <span>ENCRYPTED TLS • RBAC ACTIVE</span>
          </div>
        </div>

        <button
          type="button"
          onClick={handleLogout}
          title="Sign out and return to Gateway Portal"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '6px',
            width: '100%',
            padding: '7px 10px',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '4px',
            color: '#f87171',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.12s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
          }}
        >
          <LogOut size={13} />
          <span>Logout / Switch Role</span>
        </button>
      </div>
    </aside>
  );
};
