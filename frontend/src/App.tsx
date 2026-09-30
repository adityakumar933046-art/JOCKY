import React, { useState, useEffect } from 'react';
import { Sidebar, PageId } from './components/Sidebar';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { SystemsPage } from './pages/SystemsPage';
import { JobsPage } from './pages/JobsPage';
import { EvidencePage } from './pages/EvidencePage';
import { FindingsPage } from './pages/FindingsPage';
import { CorrelationDashboardPage } from './pages/CorrelationDashboardPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SecurityDashboardPage } from './pages/SecurityDashboardPage';
import { AuditDashboardPage } from './pages/AuditDashboardPage';
import { SearchBarModal } from './components/SearchBarModal';

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (currentPage === 'login') {
    return <LoginPage onLoginSuccess={() => setCurrentPage('dashboard')} />;
  }

  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        backgroundColor: '#f8fafc',
        color: '#0f172a',
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
      }}
    >
      <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
        {currentPage === 'dashboard' && <DashboardPage onNavigate={setCurrentPage} />}
        {currentPage === 'systems' && <SystemsPage />}
        {currentPage === 'jobs' && <JobsPage />}
        {currentPage === 'evidence' && <EvidencePage />}
        {currentPage === 'findings' && <FindingsPage />}
        {currentPage === 'correlation' && <CorrelationDashboardPage />}
        {currentPage === 'investigations' && <InvestigationsPage />}
        {currentPage === 'reports' && <ReportsPage />}
        {currentPage === 'security' && <SecurityDashboardPage />}
        {currentPage === 'audit' && <AuditDashboardPage />}
      </main>

      <SearchBarModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </div>
  );
};

export default App;
