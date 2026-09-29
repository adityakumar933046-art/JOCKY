import React from 'react';

interface Props {
  status: string;
  type?: 'agent' | 'job' | 'severity' | 'investigation';
}

export const StatusBadge: React.FC<Props> = ({ status, type = 'job' }) => {
  const s = status.toUpperCase();

  let bg = '#f1f5f9';
  let text = '#475569';
  let border = '#cbd5e1';

  if (s === 'ONLINE' || s === 'COMPLETED' || s === 'SUCCESS' || s === 'CLOSED') {
    bg = '#ecfdf5';
    text = '#047857';
    border = '#a7f3d0';
  } else if (s === 'OFFLINE' || s === 'FAILED' || s === 'CRITICAL' || s === 'CANCELLED') {
    bg = '#fef2f2';
    text = '#b91c1c';
    border = '#fecaca';
  } else if (s === 'RUNNING' || s === 'IN_PROGRESS' || s === 'HIGH') {
    bg = '#fff7ed';
    text = '#c2410c';
    border = '#fed7aa';
  } else if (s === 'ASSIGNED' || s === 'MEDIUM') {
    bg = '#fffbeb';
    text = '#b45309';
    border = '#fde68a';
  } else if (s === 'PENDING' || s === 'LOW' || s === 'OPEN') {
    bg = '#eff6ff';
    text = '#1d4ed8';
    border = '#bfdbfe';
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '12px',
        fontWeight: 600,
        backgroundColor: bg,
        color: text,
        border: `1px solid ${border}`,
        letterSpacing: '0.02em',
      }}
    >
      {status}
    </span>
  );
};
