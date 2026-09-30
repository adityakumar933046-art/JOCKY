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
  LogOut,
  UserCheck,
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

interface NavSection {
  title: string;
  items: Array<{ id: PageId; label: string; icon: React.ReactNode }>;
}

export const Sidebar: React.FC<Props> = ({ currentPage, onNavigate }) => {
  const sections: NavSection[] = [
    {
      title: 'COMMAND',
      items: [
        { id: 'dashboard', label: 'Command Center', icon: <LayoutDashboard size={17} /> },
        { id: 'jobs', label: 'Live Analysis', icon: <PlaySquare size={17} /> },
        { id: 'systems', label: 'Systems & Trust', icon: <Server size={17} /> },
      ],
    },
    {
      title: 'FORENSICS',
      items: [
        { id: 'evidence', label: 'Evidence Records', icon: <FileSearch size={17} /> },
        { id: 'findings', label: 'Threat Findings', icon: <ShieldAlert size={17} /> },
        { id: 'correlation', label: 'Cross-System Correlation', icon: <Share2 size={17} /> },
      ],
    },
    {
      title: 'INVESTIGATIONS',
      items: [
        { id: 'investigations', label: 'Active Cases', icon: <FolderGit2 size={17} /> },
        { id: 'reports', label: 'Forensic Reports', icon: <FileText size={17} /> },
      ],
    },
    {
      title: 'SECURITY',
      items: [
        { id: 'security', label: 'Security Operations', icon: <Shield size={17} /> },
        { id: 'audit', label: 'Audit Ledger', icon: <FileSearch size={17} /> },
      ],
    },
  ];

  let currentUsername = 'analyst';
  let currentRole = 'Security Analyst';
  try {
    const rawUser = localStorage.getItem('jocky_user');
    if (rawUser) {
      const u = JSON.parse(rawUser);
      if (u.username) currentUsername = u.username;
      if (u.role) {
        currentRole = u.role.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c: string) => c.toUpperCase());
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
          padding: '20px 18px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          borderBottom: '1px solid #1e293b',
        }}
      >
        <div
          style={{
            backgroundColor: '#2563eb',
            borderRadius: '8px',
            padding: '7px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 2px 8px rgba(37, 99, 235, 0.4)',
          }}
        >
          <Shield size={20} color="#ffffff" />
        </div>
        <div>
          <div style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '0.06em', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>JOCKY</span>
            <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '4px', backgroundColor: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', fontWeight: 700, letterSpacing: '0.05em' }}>
              SIH
            </span>
          </div>
          <div style={{ fontSize: '10px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
            Forensic Command Center
          </div>
        </div>
      </div>

      {/* Navigation Links Grouped by Workflow */}
      <nav style={{ padding: '12px 10px', flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
        {sections.map((section) => (
          <div key={section.title} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            <div
              style={{
                fontSize: '10px',
                fontWeight: 700,
                color: '#64748b',
                letterSpacing: '0.1em',
                padding: '4px 10px',
                textTransform: 'uppercase',
              }}
            >
              {section.title}
            </div>
            {section.items.map((item) => {
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
                    borderRadius: '6px',
                    fontSize: '13px',
                    fontWeight: isActive ? 600 : 500,
                    color: isActive ? '#ffffff' : '#94a3b8',
                    backgroundColor: isActive ? '#2563eb' : 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    textAlign: 'left',
                    width: '100%',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = '#1e293b';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                >
                  {item.icon}
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.label}
                  </span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer User Info & Logout Button */}
      <div
        style={{
          padding: '16px 16px',
          borderTop: '1px solid #1e293b',
          fontSize: '12px',
          color: '#94a3b8',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '50%',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#38bdf8',
            }}
          >
            <UserCheck size={16} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 600, color: '#f1f5f9', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {currentUsername}
            </div>
            <div style={{ fontSize: '11px', color: '#64748b' }}>
              {currentRole}
            </div>
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
            gap: '8px',
            width: '100%',
            padding: '9px 12px',
            backgroundColor: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            borderRadius: '6px',
            color: '#f87171',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.22)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
          }}
        >
          <LogOut size={14} />
          <span>Logout / Switch Role</span>
        </button>

        <div style={{ fontSize: '10px', color: '#475569', textAlign: 'center' }}>
          JOCKY Platform v1.0.0
        </div>
      </div>
    </aside>
  );
};
