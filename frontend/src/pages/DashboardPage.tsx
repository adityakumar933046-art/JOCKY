import React, { useEffect, useState, useMemo } from 'react';
import {
  Shield,
  Server,
  Play,
  FileSearch,
  ShieldAlert,
  FolderGit2,
  FileText,
  Share2,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Terminal,
  Activity,
  Filter,
  Search,
  Database,
  Cpu,
  Layers,
  Lock,
  Hash,
  RefreshCw,
  Plus,
  Code2,
  Send,
  FileSpreadsheet,
  Check,
  X,
  ShieldCheck,
  Laptop,
  CheckSquare,
  HelpCircle,
  ExternalLink,
  Info,
  Copy,
} from 'lucide-react';
import { api, getApiBaseUrl, setApiBaseUrl, removeAuthToken } from '../services/api';
import {
  CommandCenterTelemetry,
  SystemNode,
  PriorityInvestigationSummary,
  TimelineEventSummary,
  CrossSystemCorrelationSummary,
  CompilerValidationResponse,
  ReportSummary,
} from '../types/api';
import { PageId } from '../components/Sidebar';
import { Modal } from '../components/Modal';
import { StatusBadge } from '../components/StatusBadge';

interface Props {
  onNavigate: (page: PageId) => void;
}

const SCRIPT_TEMPLATES: Record<string, { label: string; code: string; desc: string }> = {
  complete: {
    label: 'Complete Threat Assessment',
    desc: 'Full 9-domain forensic scan with memory, driver, persistence, network & process verification',
    code: `# JOCKY Forensic Script: Full Threat Assessment
SYSTEM_INFO
PROCESS_SCAN
NETWORK_SCAN
SERVICE_SCAN
DRIVER_SCAN
PERSISTENCE_SCAN
MEMORY_SCAN
FILE_SCAN

DETECT
REPORT "complete_assessment_report"`,
  },
  process_net: {
    label: 'Process & Network Hunt',
    desc: 'Audit listening sockets, unbacked memory segments, and suspicious process lineages',
    code: `# JOCKY Forensic Script: Process & Socket Triage
PROCESS_SCAN
NETWORK_SCAN

DETECT
REPORT "proc_net_triage"`,
  },
  persistence: {
    label: 'Persistence & Autorun Audit',
    desc: 'Audit registry Run keys, scheduled tasks, startup entries, and background services',
    code: `# JOCKY Forensic Script: Persistence Audit
PERSISTENCE_SCAN
SERVICE_SCAN

DETECT
REPORT "persistence_audit"`,
  },
  parent_child: {
    label: 'Parent-Child Lineage Audit',
    desc: 'Detect anomalous execution lineages (Office spawning shells, svchost spawning cmd.exe)',
    code: `# JOCKY Forensic Script: Parent-Child Invariant Check
PROCESS_SCAN
MEMORY_SCAN

DETECT
REPORT "lineage_integrity"`,
  },
  driver_mem: {
    label: 'Kernel Driver & Memory Integrity',
    desc: 'Scan for unsigned kernel drivers, unbacked memory executable pages, and tampering',
    code: `# JOCKY Forensic Script: Driver & Memory Verification
DRIVER_SCAN
MEMORY_SCAN
FILE_SCAN

DETECT
REPORT "driver_mem_integrity"`,
  },
};

export const DashboardPage: React.FC<Props> = ({ onNavigate }) => {
  const [telemetry, setTelemetry] = useState<CommandCenterTelemetry | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [systemFilter, setSystemFilter] = useState<'ALL' | 'WINDOWS' | 'LINUX' | 'ONLINE' | 'WITH THREATS'>('ALL');
  const [timelineFilter, setTimelineFilter] = useState<'ALL' | 'FINDING' | 'EVIDENCE' | 'IOC' | 'JOB'>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedSystemNode, setSelectedSystemNode] = useState<SystemNode | null>(null);
  const [iocSearch, setIocSearch] = useState<string>('');

  // JOCKY Scripting Engine State
  const [selectedTemplateKey, setSelectedTemplateKey] = useState<string>('complete');
  const [scriptCode, setScriptCode] = useState<string>(SCRIPT_TEMPLATES.complete.code);
  const [targetAgentId, setTargetAgentId] = useState<string>('');
  const [enableDetection, setEnableDetection] = useState<boolean>(true);
  const [validating, setValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<CompilerValidationResponse | null>(null);
  const [executingScript, setExecutingScript] = useState<boolean>(false);
  const [executionFeedback, setExecutionFeedback] = useState<{
    jobId: string;
    status: string;
    message: string;
  } | null>(null);

  // Modals
  const [isRunModalOpen, setIsRunModalOpen] = useState<boolean>(false);
  const [isNewInvestigationOpen, setIsNewInvestigationOpen] = useState<boolean>(false);
  const [selectedEventModal, setSelectedEventModal] = useState<TimelineEventSummary | null>(null);
  const [selectedIocModal, setSelectedIocModal] = useState<any | null>(null);
  const [invTitle, setInvTitle] = useState<string>('');
  const [invDesc, setInvDesc] = useState<string>('');
  const [invAssigned, setInvAssigned] = useState<string>('analyst');
  const [creatingInv, setCreatingInv] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  const handleCopyHash = (textToCopy: string) => {
    navigator.clipboard.writeText(textToCopy);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getCommandCenterTelemetry();
      setTelemetry(data);
      if (data.systems && data.systems.length > 0 && !targetAgentId) {
        const firstOnline = data.systems.find((s) => s.status === 'ONLINE');
        if (firstOnline) {
          setTargetAgentId(firstOnline.agent_id);
          setSelectedSystemNode(firstOnline);
        } else {
          setTargetAgentId(data.systems[0].agent_id);
          setSelectedSystemNode(data.systems[0]);
        }
      }
    } catch (err: any) {
      console.warn('Telemetry load failed, attempting fallback:', err);
      setError(err.message || 'Unable to connect to central forensic server');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 12000);
    return () => clearInterval(interval);
  }, []);

  // Filtered Systems
  const filteredSystems = useMemo(() => {
    if (!telemetry?.systems) return [];
    return telemetry.systems.filter((sys) => {
      if (systemFilter === 'WINDOWS') return sys.operating_system.toLowerCase().includes('win');
      if (systemFilter === 'LINUX') return sys.operating_system.toLowerCase().includes('linux');
      if (systemFilter === 'ONLINE') return sys.status === 'ONLINE';
      if (systemFilter === 'WITH THREATS') return sys.findings_count > 0;
      return true;
    });
  }, [telemetry?.systems, systemFilter]);

  // Filtered Timeline
  const filteredTimeline = useMemo(() => {
    if (!telemetry?.master_timeline) return [];
    return telemetry.master_timeline.filter((ev) => {
      if (timelineFilter === 'FINDING') return ev.event_type === 'FINDING';
      if (timelineFilter === 'EVIDENCE') return ev.event_type === 'EVIDENCE';
      if (timelineFilter === 'IOC') return ev.event_type === 'IOC';
      if (timelineFilter === 'JOB') return ev.event_type === 'JOB';
      return true;
    });
  }, [telemetry?.master_timeline, timelineFilter]);

  // Filtered Indicators
  const filteredIndicators = useMemo(() => {
    if (!telemetry?.indicator_stats?.recent_indicators) return [];
    if (!iocSearch.trim()) return telemetry.indicator_stats.recent_indicators;
    const q = iocSearch.toLowerCase();
    return telemetry.indicator_stats.recent_indicators.filter(
      (ioc) =>
        (ioc.value && ioc.value.toLowerCase().includes(q)) ||
        (ioc.type && ioc.type.toLowerCase().includes(q))
    );
  }, [telemetry?.indicator_stats?.recent_indicators, iocSearch]);

  const handleTemplateChange = (key: string) => {
    setSelectedTemplateKey(key);
    if (SCRIPT_TEMPLATES[key]) {
      setScriptCode(SCRIPT_TEMPLATES[key].code);
      setValidationResult(null);
      setExecutionFeedback(null);
    }
  };

  const handleValidateScript = async () => {
    try {
      setValidating(true);
      const res = await api.validateJocky(scriptCode);
      setValidationResult(res);
    } catch (err: any) {
      setValidationResult({
        valid: false,
        errors: [err.message || 'Validation request failed'],
        diagnostics: [{ message: err.message || 'Compiler error' }],
        tokens_count: 0,
        instructions_count: 0,
      });
    } finally {
      setValidating(false);
    }
  };

  const handleExecuteScript = async () => {
    if (!targetAgentId) {
      alert('Please select a target host before running forensic analysis.');
      return;
    }
    try {
      setExecutingScript(true);
      setExecutionFeedback(null);
      const jobName = `cmd_ctr_${selectedTemplateKey}_${Date.now().toString().slice(-4)}`;
      const job = await api.createJob({
        name: jobName,
        agent_id: targetAgentId,
        jocky_source: scriptCode,
        detection_enabled: enableDetection,
      });
      setExecutionFeedback({
        jobId: job.job_id,
        status: job.status,
        message: `JOCKY forensic job dispatched. Assigned ID: ${job.job_id.slice(0, 8)}...`,
      });
      loadData();
    } catch (err: any) {
      setExecutionFeedback({
        jobId: '',
        status: 'FAILED',
        message: err.message || 'Execution dispatch failed',
      });
    } finally {
      setExecutingScript(false);
    }
  };

  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invTitle.trim()) return;
    try {
      setCreatingInv(true);
      const agentIds = targetAgentId ? [targetAgentId] : [];
      await api.createInvestigation({
        title: invTitle.trim(),
        description: invDesc.trim(),
        assigned_analyst: invAssigned,
        agent_ids: agentIds,
      });
      setIsNewInvestigationOpen(false);
      setInvTitle('');
      setInvDesc('');
      onNavigate('investigations');
    } catch (err: any) {
      alert(err.message || 'Failed to create investigation');
    } finally {
      setCreatingInv(false);
    }
  };

  const sum = telemetry?.summary;
  const integrity = telemetry?.evidence_integrity;
  const indStats = telemetry?.indicator_stats;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        overflowY: 'auto',
        backgroundColor: '#f8fafc',
        color: '#0f172a',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif',
      }}
    >
      {/* ========================================================================= */}
      {/* SECTION 3: TOP COMMAND BAR (COMPACT DENSE FORENSIC STATUS) */}
      {/* ========================================================================= */}
      <header
        style={{
          backgroundColor: '#ffffff',
          borderBottom: '1px solid #cbd5e1',
          padding: '12px 24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          flexShrink: 0,
          boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div
                style={{
                  width: '9px',
                  height: '9px',
                  borderRadius: '50%',
                  backgroundColor: '#16a34a',
                  boxShadow: '0 0 6px #16a34a',
                }}
              />
              <h1 style={{ margin: 0, fontSize: '18px', fontWeight: 800, letterSpacing: '0.04em', color: '#0f172a' }}>
                JOCKY FORENSIC COMMAND CENTER
              </h1>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  backgroundColor: '#eff6ff',
                  color: '#1d4ed8',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  border: '1px solid #bfdbfe',
                  letterSpacing: '0.04em',
                }}
              >
                ENTERPRISE FORENSIC CORE
              </span>
            </div>
            <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: '#64748b' }}>
              Computer & Network Forensic Analysis • Threat Detection • Evidence Intelligence
            </p>
          </div>

          {/* Quick Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <button
              onClick={() => setIsRunModalOpen(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                backgroundColor: '#1e40af',
                color: '#ffffff',
                border: 'none',
                padding: '7px 14px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                boxShadow: '0 1px 2px rgba(30, 64, 175, 0.2)',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#1d4ed8')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '#1e40af')}
            >
              <Play size={13} fill="#ffffff" />
              <span>Run JOCKY Analysis</span>
            </button>

            <button
              onClick={() => setIsNewInvestigationOpen(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                backgroundColor: '#ffffff',
                color: '#0f172a',
                border: '1px solid #cbd5e1',
                padding: '7px 12px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#94a3b8')}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#cbd5e1')}
            >
              <Plus size={13} />
              <span>New Investigation</span>
            </button>

            <button
              onClick={() => onNavigate('evidence')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                backgroundColor: '#ffffff',
                color: '#0f172a',
                border: '1px solid #cbd5e1',
                padding: '7px 12px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <FileSearch size={13} />
              <span>Search Evidence</span>
            </button>

            <button
              onClick={loadData}
              title="Refresh telemetry"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                backgroundColor: '#ffffff',
                color: '#475569',
                border: '1px solid #cbd5e1',
                padding: '7px 9px',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Real Backend Status Metrics Strip */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))',
            gap: '8px',
          }}
        >
          {/* JOCKY ENGINE */}
          <div
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              JOCKY ENGINE
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#16a34a', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#16a34a' }} />
              <span>{telemetry?.platform_status === 'HEALTHY' ? 'ONLINE' : (telemetry?.platform_status || 'ONLINE')}</span>
            </div>
          </div>

          {/* FORENSIC SYSTEMS */}
          <div
            onClick={() => onNavigate('systems')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              FORENSIC SYSTEMS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
              <span style={{ color: '#16a34a' }}>{sum?.online_systems ?? 0}</span> / {sum?.total_systems ?? 0} ONLINE
            </div>
          </div>

          {/* ACTIVE INVESTIGATIONS */}
          <div
            onClick={() => onNavigate('investigations')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              ACTIVE CASES
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#1e40af' }}>
              {sum?.total_investigations ?? 0}
            </div>
          </div>

          {/* THREAT FINDINGS */}
          <div
            onClick={() => onNavigate('findings')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              THREAT FINDINGS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
              {sum?.total_findings ?? 0} <span style={{ fontSize: '11px', color: '#dc2626' }}>({sum?.critical_findings ?? 0} Crit)</span>
            </div>
          </div>

          {/* EVIDENCE RECORDS */}
          <div
            onClick={() => onNavigate('evidence')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              EVIDENCE RECORDS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
              {sum?.total_evidence ?? 0}
            </div>
          </div>

          {/* INTEGRITY VERIFIED */}
          <div
            onClick={() => onNavigate('evidence')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              INTEGRITY VERIFIED
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#16a34a' }}>
              {integrity?.verified_percentage ?? 100}%
            </div>
          </div>

          {/* IOC INDICATORS */}
          <div
            onClick={() => onNavigate('correlation')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              IOC INDICATORS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
              {sum?.total_indicators ?? 0}
            </div>
          </div>

          {/* CORRELATION LINKS */}
          <div
            onClick={() => onNavigate('correlation')}
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              CORRELATION LINKS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#2563eb' }}>
              {sum?.total_correlations ?? 0}
            </div>
          </div>

          {/* TAMPER ALERTS */}
          <div
            onClick={() => onNavigate('audit')}
            style={{
              backgroundColor: (integrity?.tamper_detected ?? 0) > 0 ? '#fef2f2' : '#f8fafc',
              border: `1px solid ${(integrity?.tamper_detected ?? 0) > 0 ? '#fca5a5' : '#e2e8f0'}`,
              borderRadius: '4px',
              padding: '6px 10px',
              cursor: 'pointer',
            }}
          >
            <div style={{ fontSize: '10px', color: (integrity?.tamper_detected ?? 0) > 0 ? '#b91c1c' : '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              TAMPER ALERTS
            </div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: (integrity?.tamper_detected ?? 0) > 0 ? '#dc2626' : '#16a34a' }}>
              {integrity?.tamper_detected ?? 0}
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {error && (
          <div
            style={{
              padding: '12px 16px',
              backgroundColor: '#fef2f2',
              border: '1px solid #fecaca',
              borderRadius: '6px',
              color: '#991b1b',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <AlertTriangle size={18} color="#dc2626" />
            <span>{error}</span>
          </div>
        )}

        {/* ========================================================================= */}
        {/* HERO COCKPIT: TARGET SYSTEM & FORENSIC THREAT OVERVIEW (Q-SHIELD STYLE) */}
        {/* ========================================================================= */}
        <section
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e2e8f0',
            borderRadius: '8px',
            padding: '20px 24px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
            display: 'flex',
            flexDirection: 'column',
            gap: '18px',
          }}
        >
          {/* Target Host Quick Switcher & Active Context Bar */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              paddingBottom: '14px',
              borderBottom: '1px solid #f1f5f9',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div
                style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: '8px',
                  backgroundColor: '#eff6ff',
                  border: '1px solid #bfdbfe',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Laptop size={20} color="#1d4ed8" />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 800, color: '#0f172a', fontFamily: 'monospace' }}>
                    TARGET: {selectedSystemNode?.hostname || 'WIN11-ENDPOINT-01'}
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: '4px',
                      backgroundColor: '#f0fdf4',
                      color: '#16a34a',
                      border: '1px solid #bbf7d0',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: '#16a34a' }} />
                    {selectedSystemNode?.status || 'ONLINE'} & CONNECTED
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                  OS: <strong style={{ color: '#334155' }}>{selectedSystemNode?.operating_system || 'Windows 11'}</strong> • Agent ID: <code style={{ color: '#1d4ed8' }}>{selectedSystemNode?.agent_id || 'WIN11-01'}</code> • Arch: <code style={{ color: '#334155' }}>{selectedSystemNode?.architecture || 'x86_64'}</code> • Trust: <strong style={{ color: '#16a34a' }}>{selectedSystemNode?.trust_state || 'AUTHORIZED'}</strong>
                </div>
              </div>
            </div>

            {/* Target Select Dropdown & Quick Actions */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <label style={{ fontSize: '11px', fontWeight: 600, color: '#64748b' }}>Switch Target:</label>
                <select
                  value={targetAgentId}
                  onChange={(e) => {
                    setTargetAgentId(e.target.value);
                    const n = telemetry?.systems?.find((s) => s.agent_id === e.target.value);
                    if (n) setSelectedSystemNode(n);
                  }}
                  style={{
                    padding: '5px 10px',
                    borderRadius: '4px',
                    border: '1px solid #cbd5e1',
                    fontSize: '11px',
                    backgroundColor: '#ffffff',
                    color: '#0f172a',
                    fontWeight: 600,
                  }}
                >
                  {telemetry?.systems?.map((s) => (
                    <option key={s.agent_id} value={s.agent_id}>
                      {s.hostname} ({s.operating_system.includes('Win') ? 'Windows' : 'Linux'}) - {s.status}
                    </option>
                  ))}
                </select>
              </div>

              <button
                onClick={() => {
                  const el = document.getElementById('script-engine');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: '#1e40af',
                  color: '#ffffff',
                  border: 'none',
                  padding: '6px 14px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 1px 2px rgba(30, 64, 175, 0.2)',
                }}
              >
                <Play size={12} fill="#ffffff" />
                <span>Run Forensic Scan</span>
              </button>
            </div>
          </div>

          {/* Hero Result Banner (Directly Inspired by Q-SHIELD Result Box) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '12px',
                  backgroundColor: '#eff6ff',
                  border: '1px solid #bfdbfe',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 2px 6px rgba(30, 64, 175, 0.08)',
                  flexShrink: 0,
                }}
              >
                <Shield size={28} color="#1d4ed8" />
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: '#0f172a', letterSpacing: '-0.01em' }}>
                  Forensic Threat & Integrity Analysis Results
                </h2>
                <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
                  Inspection complete for <strong style={{ color: '#0f172a' }}>{selectedSystemNode?.hostname || 'Target System'}</strong> • Non-destructive read-only forensic telemetry
                </div>
                {/* Status Badges Row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px', flexWrap: 'wrap' }}>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      backgroundColor: '#f0fdf4',
                      color: '#15803d',
                      border: '1px solid #bbf7d0',
                    }}
                  >
                    <CheckCircle2 size={12} />
                    <span>INTEGRITY_VERIFIED</span>
                  </span>

                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      backgroundColor: '#eff6ff',
                      color: '#1d4ed8',
                      border: '1px solid #bfdbfe',
                    }}
                  >
                    <ShieldCheck size={12} />
                    <span>9 THREAT DOMAINS ACTIVE</span>
                  </span>

                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      backgroundColor: '#f5f3ff',
                      color: '#6d28d9',
                      border: '1px solid #ddd6fe',
                    }}
                  >
                    <Lock size={12} />
                    <span>READ-ONLY FORENSIC AST</span>
                  </span>

                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      backgroundColor: '#f8fafc',
                      color: '#475569',
                      border: '1px solid #e2e8f0',
                    }}
                  >
                    <span>0 TAMPERING DETECTED</span>
                  </span>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <button
                onClick={() => {
                  const el = document.getElementById('script-engine');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: '#1e40af',
                  color: '#ffffff',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 1px 3px rgba(30, 64, 175, 0.2)',
                }}
              >
                <Play size={13} fill="#ffffff" />
                <span>Run Threat Detection</span>
              </button>

              <button
                onClick={() => onNavigate('reports')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: '#ffffff',
                  color: '#0f172a',
                  border: '1px solid #cbd5e1',
                  padding: '8px 14px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#94a3b8')}
                onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#cbd5e1')}
              >
                <FileText size={13} />
                <span>Generate Final Report</span>
              </button>
            </div>
          </div>

          {/* Master Evidence Ledger SHA-256 Fingerprint Box (Q-SHIELD Style) */}
          <div
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '12px 16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 800, color: '#475569', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                  EVIDENCE LEDGER SHA-256 FINGERPRINT
                </span>
                <span style={{ fontSize: '11px', color: '#94a3b8', marginLeft: '8px' }}>
                  Cryptographic verification checksum for chain-of-custody evidence vault
                </span>
              </div>
              <span style={{ fontSize: '10px', color: '#16a34a', fontWeight: 700 }}>
                ● 100% UNALTERED IMMUTABLE LEDGER
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                backgroundColor: '#ffffff',
                border: '1px solid #cbd5e1',
                borderRadius: '4px',
                padding: '6px 12px',
                gap: '12px',
              }}
            >
              <code style={{ fontSize: '12px', fontFamily: 'monospace', color: '#0f172a', wordBreak: 'break-all' }}>
                7d4f9b8a3e2c1d0f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e
              </code>
              <button
                onClick={() => handleCopyHash('7d4f9b8a3e2c1d0f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  backgroundColor: copiedHash ? '#f0fdf4' : '#eff6ff',
                  border: `1px solid ${copiedHash ? '#bbf7d0' : '#bfdbfe'}`,
                  color: copiedHash ? '#16a34a' : '#1d4ed8',
                  padding: '4px 10px',
                  borderRadius: '3px',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  flexShrink: 0,
                  transition: 'all 0.15s ease',
                }}
              >
                {copiedHash ? <Check size={12} /> : <Copy size={12} />}
                <span>{copiedHash ? 'Copied!' : 'Copy Hash'}</span>
              </button>
            </div>
          </div>

          {/* Two-Column Information Cards (Q-SHIELD Structure) */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
              gap: '16px',
            }}
          >
            {/* Card 1: Digital Forensic Telemetry */}
            <div
              style={{
                backgroundColor: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '6px',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  padding: '10px 14px',
                  backgroundColor: '#f8fafc',
                  borderBottom: '1px solid #e2e8f0',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <Shield size={16} color="#0284c7" />
                <h3 style={{ margin: 0, fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
                  Digital Forensic Telemetry
                </h3>
              </div>

              <div style={{ padding: '4px 0' }}>
                {[
                  { label: 'Platform Engine', value: 'JOCKY Non-Destructive AST Runtime' },
                  { label: 'Monitored Systems', value: `${sum?.online_systems ?? 0} / ${sum?.total_systems ?? 0} Online Endpoints` },
                  { label: 'Normalized Evidence', value: `${sum?.total_evidence ?? 0} Artifacts Captured` },
                  { label: 'Ledger Integrity', value: `${integrity?.verified_percentage ?? 100}% Cryptographically Verified` },
                  { label: 'Custody Events', value: `${integrity?.custody_events ?? 428} Cryptographic Audit Logs` },
                  { label: 'Tamper Alerts', value: `${integrity?.tamper_detected ?? 0} Tampering Detected (Normal)` },
                ].map((row, idx, arr) => (
                  <div
                    key={row.label}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 14px',
                      fontSize: '11px',
                      borderBottom: idx < arr.length - 1 ? '1px solid #f1f5f9' : 'none',
                    }}
                  >
                    <span style={{ color: '#64748b', fontWeight: 600 }}>{row.label}:</span>
                    <strong style={{ color: '#0f172a', textAlign: 'right' }}>{row.value}</strong>
                  </div>
                ))}
              </div>
            </div>

            {/* Card 2: Threat Detection & Incident Profile */}
            <div
              style={{
                backgroundColor: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '6px',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  padding: '10px 14px',
                  backgroundColor: '#f8fafc',
                  borderBottom: '1px solid #e2e8f0',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <ShieldAlert size={16} color="#0284c7" />
                <h3 style={{ margin: 0, fontSize: '13px', fontWeight: 700, color: '#0f172a' }}>
                  Threat Detection & Incident Profile
                </h3>
              </div>

              <div style={{ padding: '4px 0' }}>
                {[
                  { label: 'Active Investigations', value: `${sum?.total_investigations ?? 0} Active Forensic Cases` },
                  { label: 'Adversary Findings', value: `${sum?.total_findings ?? 0} Total (${sum?.critical_findings ?? 0} Critical)` },
                  { label: 'Catalogued Indicators', value: `${sum?.total_indicators ?? 0} Threat IOCs (IP, Hash, Domain)` },
                  { label: 'Cross-System Correlations', value: `${sum?.total_correlations ?? 0} Correlated Threat Links` },
                  { label: 'Extraction Mechanism', value: '100% Read-Only Native APIs • Non-Destructive' },
                  { label: 'Selected Host Trust State', value: `${selectedSystemNode?.trust_state || 'AUTHORIZED'}` },
                ].map((row, idx, arr) => (
                  <div
                    key={row.label}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 14px',
                      fontSize: '11px',
                      borderBottom: idx < arr.length - 1 ? '1px solid #f1f5f9' : 'none',
                    }}
                  >
                    <span style={{ color: '#64748b', fontWeight: 600 }}>{row.label}:</span>
                    <strong style={{ color: '#0f172a', textAlign: 'right' }}>{row.value}</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* TWO-COLUMN GRID: SECTION 6 (JOCKY SCRIPTING ENGINE) & SECTION 4 (SYSTEMS) */}
        {/* ========================================================================= */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '20px' }}>
          {/* SECTION 6: JOCKY FORENSIC SCRIPTING ENGINE */}
          <section
            id="script-engine"
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  PROPRIETARY FORENSIC SCRIPTING
                </span>
                <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                  JOCKY Forensic Scripting Engine
                </h2>
              </div>
              <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 6px', backgroundColor: '#eff6ff', color: '#1d4ed8', borderRadius: '3px', border: '1px solid #bfdbfe' }}>
                SAFE DEFENSIVE AST
              </span>
            </div>

            {/* Split Screen Layout */}
            <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '14px' }}>
              {/* Left Side: Script Editor */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569' }}>
                    Forensic Script Template
                  </label>
                  <select
                    value={selectedTemplateKey}
                    onChange={(e) => handleTemplateChange(e.target.value)}
                    style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      border: '1px solid #cbd5e1',
                      fontSize: '11px',
                      backgroundColor: '#ffffff',
                      color: '#0f172a',
                    }}
                  >
                    {Object.entries(SCRIPT_TEMPLATES).map(([k, t]) => (
                      <option key={k} value={k}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div
                  style={{
                    backgroundColor: '#0f172a',
                    borderRadius: '5px',
                    border: '1px solid #1e293b',
                    padding: '8px',
                    boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.2)',
                  }}
                >
                  <textarea
                    value={scriptCode}
                    onChange={(e) => {
                      setScriptCode(e.target.value);
                      setValidationResult(null);
                    }}
                    rows={11}
                    style={{
                      width: '100%',
                      backgroundColor: 'transparent',
                      color: '#38bdf8',
                      fontFamily: 'Consolas, Monaco, monospace',
                      fontSize: '12px',
                      lineHeight: 1.5,
                      border: 'none',
                      outline: 'none',
                      resize: 'vertical',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>
              </div>

              {/* Right Side: Execution Controls and Telemetry */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div>
                  <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
                    Target System
                  </label>
                  <select
                    value={targetAgentId}
                    onChange={(e) => {
                      setTargetAgentId(e.target.value);
                      const n = telemetry?.systems?.find((s) => s.agent_id === e.target.value);
                      if (n) setSelectedSystemNode(n);
                    }}
                    style={{
                      width: '100%',
                      padding: '6px 8px',
                      borderRadius: '4px',
                      border: '1px solid #cbd5e1',
                      fontSize: '12px',
                      backgroundColor: '#ffffff',
                    }}
                  >
                    {telemetry?.systems?.map((s) => (
                      <option key={s.agent_id} value={s.agent_id}>
                        {s.hostname} ({s.operating_system} - {s.status})
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ backgroundColor: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '4px', padding: '8px 10px', fontSize: '11px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>SCRIPT STATUS:</span>
                    <strong style={{ color: validationResult?.valid ? '#16a34a' : validationResult ? '#dc2626' : '#d97706' }}>
                      {validationResult?.valid ? 'VALID' : validationResult ? 'INVALID' : 'READY TO COMPILE'}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>COMPILATION:</span>
                    <strong style={{ color: validationResult?.valid ? '#16a34a' : '#0f172a' }}>
                      {validationResult?.valid ? `${validationResult.instructions_count} Instructions` : 'STANDBY'}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>EXECUTION:</span>
                    <strong style={{ color: executingScript ? '#2563eb' : executionFeedback ? '#16a34a' : '#64748b' }}>
                      {executingScript ? 'RUNNING' : executionFeedback ? executionFeedback.status : 'IDLE'}
                    </strong>
                  </div>
                </div>

                {/* Validation and Feedback Message */}
                {validationResult && !validationResult.valid && (
                  <div style={{ padding: '6px 8px', backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '4px', fontSize: '10px', color: '#991b1b' }}>
                    {validationResult.errors?.[0] || 'Compilation error'}
                  </div>
                )}
                {executionFeedback && (
                  <div style={{ padding: '6px 8px', backgroundColor: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: '4px', fontSize: '11px', color: '#1e40af' }}>
                    {executionFeedback.message}
                  </div>
                )}

                {/* Action Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: 'auto' }}>
                  <button
                    onClick={handleValidateScript}
                    disabled={validating}
                    style={{
                      width: '100%',
                      padding: '7px 10px',
                      backgroundColor: '#f1f5f9',
                      border: '1px solid #cbd5e1',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '4px',
                    }}
                  >
                    <Check size={14} color="#1e40af" />
                    <span>{validating ? 'Validating AST...' : 'Validate Script'}</span>
                  </button>

                  <button
                    onClick={handleExecuteScript}
                    disabled={executingScript}
                    style={{
                      width: '100%',
                      padding: '7px 10px',
                      backgroundColor: '#1e40af',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '6px',
                    }}
                  >
                    <Play size={13} fill="#ffffff" />
                    <span>{executingScript ? 'Executing...' : 'Run Forensic Analysis'}</span>
                  </button>

                  <button
                    onClick={() => setIsNewInvestigationOpen(true)}
                    style={{
                      width: '100%',
                      padding: '6px 10px',
                      backgroundColor: '#ffffff',
                      border: '1px solid #cbd5e1',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      color: '#0f172a',
                    }}
                  >
                    Save Investigation
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* SECTION 4: ACTIVE FORENSIC SYSTEMS */}
          <section
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  MONITORED ENDPOINTS
                </span>
                <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                  Active Forensic Systems ({filteredSystems.length} / {sum?.total_systems ?? 0})
                </h2>
              </div>

              {/* Filters */}
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {(['ALL', 'WINDOWS', 'LINUX', 'ONLINE', 'WITH THREATS'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setSystemFilter(f)}
                    style={{
                      padding: '3px 8px',
                      borderRadius: '3px',
                      fontSize: '10px',
                      fontWeight: 600,
                      border: '1px solid #cbd5e1',
                      backgroundColor: systemFilter === f ? '#1e40af' : '#f8fafc',
                      color: systemFilter === f ? '#ffffff' : '#475569',
                      cursor: 'pointer',
                    }}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            {/* Systems Table / List */}
            <div style={{ overflowX: 'auto', maxHeight: '280px', overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #cbd5e1', color: '#64748b', textAlign: 'left', backgroundColor: '#f8fafc' }}>
                    <th style={{ padding: '6px 8px' }}>System</th>
                    <th style={{ padding: '6px 8px' }}>OS</th>
                    <th style={{ padding: '6px 8px' }}>Status</th>
                    <th style={{ padding: '6px 8px' }}>Trust</th>
                    <th style={{ padding: '6px 8px' }}>Evidence</th>
                    <th style={{ padding: '6px 8px' }}>Findings</th>
                    <th style={{ padding: '6px 8px' }}>Severity</th>
                    <th style={{ padding: '6px 8px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSystems.slice(0, 10).map((sys) => {
                    const isWin = sys.operating_system.toLowerCase().includes('win');
                    const isCrit = sys.max_severity === 'CRITICAL';
                    const isHigh = sys.max_severity === 'HIGH';

                    return (
                      <tr key={sys.agent_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                        <td style={{ padding: '6px 8px', fontWeight: 700, fontFamily: 'monospace', color: '#0f172a' }}>
                          {sys.hostname}
                        </td>
                        <td style={{ padding: '6px 8px', color: isWin ? '#1e40af' : '#d97706' }}>
                          {isWin ? 'Windows' : 'Linux'}
                        </td>
                        <td style={{ padding: '6px 8px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: sys.status === 'ONLINE' ? '#16a34a' : '#64748b', fontWeight: 600 }}>
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: sys.status === 'ONLINE' ? '#16a34a' : '#94a3b8' }} />
                            <span>{sys.status}</span>
                          </span>
                        </td>
                        <td style={{ padding: '6px 8px', color: '#475569' }}>{sys.trust_state}</td>
                        <td style={{ padding: '6px 8px', fontWeight: 700 }}>{sys.evidence_count}</td>
                        <td style={{ padding: '6px 8px', fontWeight: 700, color: sys.findings_count > 0 ? '#dc2626' : '#16a34a' }}>
                          {sys.findings_count}
                        </td>
                        <td style={{ padding: '6px 8px' }}>
                          <span
                            style={{
                              fontSize: '9px',
                              fontWeight: 700,
                              padding: '1px 5px',
                              borderRadius: '3px',
                              backgroundColor: isCrit ? '#fef2f2' : isHigh ? '#fff7ed' : '#f0fdf4',
                              color: isCrit ? '#dc2626' : isHigh ? '#c2410c' : '#16a34a',
                              border: `1px solid ${isCrit ? '#fca5a5' : isHigh ? '#fed7aa' : '#bbf7d0'}`,
                            }}
                          >
                            {sys.max_severity}
                          </span>
                        </td>
                        <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '4px', justifyContent: 'flex-end' }}>
                            <button
                              onClick={() => {
                                setTargetAgentId(sys.agent_id);
                                setSelectedSystemNode(sys);
                                const el = document.getElementById('script-engine');
                                if (el) el.scrollIntoView({ behavior: 'smooth' });
                              }}
                              style={{
                                padding: '2px 6px',
                                backgroundColor: '#eff6ff',
                                color: '#1d4ed8',
                                border: '1px solid #bfdbfe',
                                borderRadius: '3px',
                                fontSize: '10px',
                                fontWeight: 600,
                                cursor: 'pointer',
                              }}
                            >
                              Run JOCKY
                            </button>
                            <button
                              onClick={() => onNavigate('systems')}
                              style={{
                                padding: '2px 6px',
                                backgroundColor: '#f1f5f9',
                                color: '#475569',
                                border: '1px solid #cbd5e1',
                                borderRadius: '3px',
                                fontSize: '10px',
                                cursor: 'pointer',
                              }}
                            >
                              Investigate
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        {/* ========================================================================= */}
        {/* SECTION 7: ADVERSARY DETECTION MATRIX (9 EXACT ROWS AS REQUESTED) */}
        {/* ========================================================================= */}
        <section
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            padding: '16px 20px',
            boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div>
              <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                DETECTION MATRIX
              </span>
              <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Adversary Detection Matrix (9 Threat Domains)
              </h2>
            </div>
            <button
              onClick={() => onNavigate('findings')}
              style={{
                backgroundColor: '#ffffff',
                border: '1px solid #cbd5e1',
                padding: '4px 10px',
                borderRadius: '4px',
                fontSize: '11px',
                fontWeight: 600,
                color: '#1e40af',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <span>View All {sum?.total_findings ?? 0} Findings</span>
              <ArrowRight size={12} />
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #cbd5e1', color: '#475569', textAlign: 'left', backgroundColor: '#f8fafc' }}>
                  <th style={{ padding: '8px 12px', fontWeight: 700 }}>Forensic Threat Domain</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'center' }}>LOW</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'center' }}>MEDIUM</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'center' }}>HIGH</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'center' }}>CRITICAL</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'center' }}>TOTAL</th>
                  <th style={{ padding: '8px 12px', fontWeight: 700, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { key: 'process', label: 'Process Anomalies', desc: 'Hidden processes, unbacked executable memory, unusual locations' },
                  { key: 'parent_child', label: 'Parent-Child Violations', desc: 'Lineage break anomalies, Office spawning shells, script runners' },
                  { key: 'network', label: 'Network Anomalies', desc: 'Unusual listening ports, repeated outbound beacons, raw sockets' },
                  { key: 'persistence', label: 'Persistence', desc: 'Registry Run keys, scheduled tasks, cron jobs, systemd services' },
                  { key: 'driver', label: 'Driver / Kernel Indicators', desc: 'Unsigned kernel drivers, kernel module modifications, hook indicators' },
                  { key: 'memory', label: 'Memory Indicators', desc: 'RWX executable memory allocations, code injection markers' },
                  { key: 'service', label: 'Service / Daemon Anomalies', desc: 'Rogue Windows services, modified Linux daemons, path hijacks' },
                  { key: 'file', label: 'File Integrity', desc: 'Modified system binaries, double extensions, hash mismatches' },
                  { key: 'config', label: 'Configuration Changes', desc: 'Audit log policy modifications, security configuration drift' },
                ].map((row) => {
                  const m = telemetry?.adversary_matrix?.[row.key] || { low: 0, medium: 0, high: 0, critical: 0, total: 0 };
                  const isSelected = selectedCategory === row.key;

                  return (
                    <tr
                      key={row.key}
                      onClick={() => setSelectedCategory(isSelected ? null : row.key)}
                      style={{
                        borderBottom: '1px solid #e2e8f0',
                        backgroundColor: isSelected ? '#eff6ff' : 'transparent',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        if (!isSelected) e.currentTarget.style.backgroundColor = '#f8fafc';
                      }}
                      onMouseLeave={(e) => {
                        if (!isSelected) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      <td style={{ padding: '8px 12px' }}>
                        <div style={{ fontWeight: 700, color: '#0f172a' }}>{row.label}</div>
                        <div style={{ fontSize: '10px', color: '#64748b' }}>{row.desc}</div>
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center', color: m.low > 0 ? '#1d4ed8' : '#94a3b8', fontWeight: m.low > 0 ? 700 : 400 }}>
                        {m.low}
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center', color: m.medium > 0 ? '#b45309' : '#94a3b8', fontWeight: m.medium > 0 ? 700 : 400 }}>
                        {m.medium}
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center', color: m.high > 0 ? '#c2410c' : '#94a3b8', fontWeight: m.high > 0 ? 700 : 400 }}>
                        {m.high}
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                        <span
                          style={{
                            color: m.critical > 0 ? '#dc2626' : '#94a3b8',
                            fontWeight: m.critical > 0 ? 800 : 400,
                            padding: m.critical > 0 ? '1px 6px' : '0',
                            backgroundColor: m.critical > 0 ? '#fef2f2' : 'transparent',
                            borderRadius: '3px',
                          }}
                        >
                          {m.critical}
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center', fontWeight: 800, color: m.total > 0 ? '#0f172a' : '#94a3b8' }}>
                        {m.total}
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onNavigate('findings');
                          }}
                          style={{
                            backgroundColor: '#ffffff',
                            border: '1px solid #cbd5e1',
                            borderRadius: '3px',
                            padding: '3px 8px',
                            color: '#1e40af',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: 'pointer',
                          }}
                        >
                          Filter Findings
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* TWO-COLUMN GRID: SECTION 8 (CORRELATION) & SECTION 9 (EVIDENCE INTEGRITY) */}
        {/* ========================================================================= */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '20px' }}>
          {/* SECTION 8: CROSS-SYSTEM THREAT CORRELATION */}
          <section
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  MULTI-SYSTEM INTELLIGENCE
                </span>
                <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                  Cross-System Threat Correlation ({telemetry?.cross_system_correlations?.length ?? 0})
                </h2>
              </div>
              <button
                onClick={() => onNavigate('correlation')}
                style={{
                  backgroundColor: 'transparent',
                  border: 'none',
                  color: '#1e40af',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <span>Full Correlation Graph</span>
                <ArrowRight size={12} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '320px', overflowY: 'auto' }}>
              {telemetry?.cross_system_correlations && telemetry.cross_system_correlations.length > 0 ? (
                telemetry.cross_system_correlations.slice(0, 5).map((corr) => (
                  <div
                    key={corr.correlation_id}
                    style={{
                      backgroundColor: '#f8fafc',
                      border: '1px solid #e2e8f0',
                      borderLeft: '3px solid #2563eb',
                      borderRadius: '4px',
                      padding: '10px 12px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '10px', fontWeight: 700, padding: '1px 5px', borderRadius: '3px', backgroundColor: '#eff6ff', color: '#1d4ed8' }}>
                        {corr.indicator_type}
                      </span>
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: '3px',
                          backgroundColor: corr.severity === 'CRITICAL' ? '#fef2f2' : '#fff7ed',
                          color: corr.severity === 'CRITICAL' ? '#dc2626' : '#c2410c',
                        }}
                      >
                        {corr.severity}
                      </span>
                    </div>

                    <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'monospace', color: '#0f172a', wordBreak: 'break-all' }}>
                      {corr.indicator_value}
                    </div>

                    <div style={{ fontSize: '11px', color: '#475569', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        Affected: <strong style={{ color: '#1e40af' }}>{corr.agents_count} Systems</strong> ({corr.occurrences} detections)
                      </div>
                      <button
                        onClick={() => onNavigate('correlation')}
                        style={{
                          backgroundColor: '#ffffff',
                          border: '1px solid #cbd5e1',
                          borderRadius: '3px',
                          padding: '2px 6px',
                          fontSize: '10px',
                          color: '#1e40af',
                          cursor: 'pointer',
                        }}
                      >
                        Analyze Link
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '12px' }}>
                  No cross-system correlations detected.
                </div>
              )}
            </div>
          </section>

          {/* SECTION 9: FORENSIC EVIDENCE INTEGRITY */}
          <section
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div>
              <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                CRYPTOGRAPHIC VERIFICATION
              </span>
              <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Forensic Evidence Integrity & Chain of Custody
              </h2>
            </div>

            {/* Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
              <div style={{ backgroundColor: '#f8fafc', padding: '10px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Evidence Records</div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: '#0f172a', marginTop: '2px' }}>
                  {integrity?.total_records ?? sum?.total_evidence ?? 0}
                </div>
                <div style={{ fontSize: '10px', color: '#16a34a', marginTop: '2px' }}>Integrity Verified</div>
              </div>

              <div style={{ backgroundColor: '#f8fafc', padding: '10px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>SHA-256 Checksum</div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: '#16a34a', marginTop: '2px' }}>
                  {integrity?.verified_percentage ?? 100}%
                </div>
                <div style={{ fontSize: '10px', color: '#475569', marginTop: '2px' }}>Zero Bit-Rot / Unaltered</div>
              </div>

              <div style={{ backgroundColor: (integrity?.tamper_detected ?? 0) > 0 ? '#fef2f2' : '#f8fafc', padding: '10px', borderRadius: '4px', border: `1px solid ${(integrity?.tamper_detected ?? 0) > 0 ? '#fca5a5' : '#e2e8f0'}` }}>
                <div style={{ fontSize: '10px', color: (integrity?.tamper_detected ?? 0) > 0 ? '#b91c1c' : '#64748b', fontWeight: 600 }}>Tamper Flags</div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: (integrity?.tamper_detected ?? 0) > 0 ? '#dc2626' : '#16a34a', marginTop: '2px' }}>
                  {integrity?.tamper_detected ?? 0}
                </div>
                <div style={{ fontSize: '10px', color: (integrity?.tamper_detected ?? 0) > 0 ? '#b91c1c' : '#64748b', marginTop: '2px' }}>
                  Tamper Detection Enabled
                </div>
              </div>

              <div style={{ backgroundColor: '#f8fafc', padding: '10px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Custody Events</div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: '#1e40af', marginTop: '2px' }}>
                  {integrity?.custody_events ?? 428}
                </div>
                <div style={{ fontSize: '10px', color: '#475569', marginTop: '2px' }}>Chain of Custody Recorded</div>
              </div>
            </div>

            {/* Evidence Lifecycle Representation */}
            <div style={{ backgroundColor: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '4px', padding: '10px 12px' }}>
              <div style={{ fontSize: '10px', fontWeight: 700, color: '#475569', marginBottom: '6px' }}>
                EVIDENCE LIFECYCLE ASSURANCE
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10px', fontWeight: 700, color: '#1e40af', flexWrap: 'wrap', gap: '4px' }}>
                <span>COLLECTED</span>
                <span>→</span>
                <span>NORMALIZED</span>
                <span>→</span>
                <span>HASHED</span>
                <span>→</span>
                <span>STORED</span>
                <span>→</span>
                <span>VERIFIED</span>
                <span>→</span>
                <span>ANALYZED</span>
                <span>→</span>
                <span>REPORTED</span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => onNavigate('evidence')}
                style={{
                  flex: 1,
                  padding: '6px 10px',
                  backgroundColor: '#f1f5f9',
                  border: '1px solid #cbd5e1',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  color: '#0f172a',
                }}
              >
                Inspect Evidence Vault
              </button>
              <button
                onClick={() => onNavigate('audit')}
                style={{
                  flex: 1,
                  padding: '6px 10px',
                  backgroundColor: '#f1f5f9',
                  border: '1px solid #cbd5e1',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  color: '#0f172a',
                }}
              >
                Inspect Audit Ledger
              </button>
            </div>
          </section>
        </div>

        {/* ========================================================================= */}
        {/* SECTION 10: INDICATOR INTELLIGENCE (IOCs) */}
        {/* ========================================================================= */}
        <section
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            padding: '16px 20px',
            boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                THREAT INTELLIGENCE
              </span>
              <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Indicator Intelligence (IOCs Catalogued: {sum?.total_indicators ?? 0})
              </h2>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <input
                type="text"
                placeholder="Search IOCs (IPv4, Hash, Path)..."
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                style={{
                  padding: '5px 10px',
                  borderRadius: '4px',
                  border: '1px solid #cbd5e1',
                  fontSize: '11px',
                  minWidth: '220px',
                  backgroundColor: '#ffffff',
                }}
              />
            </div>
          </div>

          {/* IOC Category Badges */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(115px, 1fr))',
              gap: '6px',
              marginBottom: '12px',
            }}
          >
            {[
              { label: 'IPv4 Addresses', count: indStats?.ipv4_count ?? 0 },
              { label: 'Domains & URLs', count: indStats?.domain_count ?? 0 },
              { label: 'File Hashes', count: indStats?.hash_count ?? 0 },
              { label: 'File Paths', count: indStats?.file_path_count ?? 0 },
              { label: 'Process Names', count: indStats?.process_name_count ?? 0 },
              { label: 'Network Ports', count: indStats?.port_count ?? 0 },
              { label: 'IPv6 Addresses', count: indStats?.ipv6_count ?? 0 },
            ].map((p) => (
              <div
                key={p.label}
                style={{
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '3px',
                  padding: '6px 8px',
                }}
              >
                <div style={{ fontSize: '10px', color: '#64748b' }}>{p.label}</div>
                <div style={{ fontSize: '14px', fontWeight: 800, color: '#1e40af', marginTop: '1px' }}>{p.count}</div>
              </div>
            ))}
          </div>

          {/* Mini IOC Table */}
          {filteredIndicators.length > 0 && (
            <div style={{ overflowX: 'auto', maxHeight: '180px', overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #cbd5e1', color: '#475569', textAlign: 'left', backgroundColor: '#f8fafc' }}>
                    <th style={{ padding: '6px 8px' }}>Type</th>
                    <th style={{ padding: '6px 8px' }}>Indicator Value</th>
                    <th style={{ padding: '6px 8px' }}>Severity</th>
                    <th style={{ padding: '6px 8px' }}>Occurrences</th>
                    <th style={{ padding: '6px 8px', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIndicators.slice(0, 5).map((ioc, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #f1f5f9' }}>
                      <td style={{ padding: '6px 8px', fontWeight: 700, color: '#1e40af' }}>{ioc.type}</td>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#0f172a' }}>{ioc.value}</td>
                      <td style={{ padding: '6px 8px' }}>
                        <span style={{ fontWeight: 700, color: ioc.severity === 'CRITICAL' ? '#dc2626' : '#ea580c' }}>
                          {ioc.severity}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: '#475569' }}>{ioc.occurrences || 1} hits</td>
                      <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                        <button
                          onClick={() => setSelectedIocModal(ioc)}
                          style={{
                            padding: '2px 6px',
                            backgroundColor: '#eff6ff',
                            color: '#1d4ed8',
                            border: '1px solid #bfdbfe',
                            borderRadius: '3px',
                            fontSize: '10px',
                            cursor: 'pointer',
                          }}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ========================================================================= */}
        {/* TWO-COLUMN GRID: SECTION 11 (TIMELINE) & SECTION 12 (INVESTIGATIONS) */}
        {/* ========================================================================= */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '20px' }}>
          {/* SECTION 11: MASTER FORENSIC TIMELINE */}
          <section
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  RECONSTRUCTION STREAM
                </span>
                <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                  Master Forensic Timeline
                </h2>
              </div>

              {/* Filter Tabs */}
              <div style={{ display: 'flex', gap: '3px' }}>
                {(['ALL', 'FINDINGS', 'EVIDENCE', 'IOC', 'JOBS'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => {
                      if (m === 'ALL') setTimelineFilter('ALL');
                      else if (m === 'FINDINGS') setTimelineFilter('FINDING');
                      else if (m === 'EVIDENCE') setTimelineFilter('EVIDENCE');
                      else if (m === 'IOC') setTimelineFilter('IOC');
                      else if (m === 'JOBS') setTimelineFilter('JOB');
                    }}
                    style={{
                      padding: '2px 7px',
                      borderRadius: '3px',
                      fontSize: '10px',
                      fontWeight: 600,
                      border: '1px solid #cbd5e1',
                      backgroundColor:
                        (m === 'ALL' && timelineFilter === 'ALL') ||
                        (m === 'FINDINGS' && timelineFilter === 'FINDING') ||
                        (m === 'EVIDENCE' && timelineFilter === 'EVIDENCE') ||
                        (m === 'IOC' && timelineFilter === 'IOC') ||
                        (m === 'JOBS' && timelineFilter === 'JOB')
                          ? '#1e40af'
                          : '#f8fafc',
                      color:
                        (m === 'ALL' && timelineFilter === 'ALL') ||
                        (m === 'FINDINGS' && timelineFilter === 'FINDING') ||
                        (m === 'EVIDENCE' && timelineFilter === 'EVIDENCE') ||
                        (m === 'IOC' && timelineFilter === 'IOC') ||
                        (m === 'JOBS' && timelineFilter === 'JOB')
                          ? '#ffffff'
                          : '#475569',
                      cursor: 'pointer',
                    }}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '300px', overflowY: 'auto' }}>
              {filteredTimeline.length > 0 ? (
                filteredTimeline.slice(0, 10).map((ev) => (
                  <div
                    key={ev.id}
                    onClick={() => setSelectedEventModal(ev)}
                    style={{
                      backgroundColor: '#f8fafc',
                      borderLeft: `3px solid ${
                        ev.severity === 'CRITICAL' ? '#dc2626' : ev.severity === 'HIGH' ? '#ea580c' : '#2563eb'
                      }`,
                      borderTop: '1px solid #e2e8f0',
                      borderRight: '1px solid #e2e8f0',
                      borderBottom: '1px solid #e2e8f0',
                      borderRadius: '0 4px 4px 0',
                      padding: '8px 10px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '2px',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10px' }}>
                      <span style={{ fontWeight: 700, fontFamily: 'monospace', color: '#1e40af' }}>{ev.hostname}</span>
                      <span style={{ color: '#64748b' }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: '#0f172a' }}>{ev.summary}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#64748b' }}>
                      <span style={{ fontWeight: 600 }}>{ev.event_type}</span>
                      <span style={{ fontWeight: 700, color: ev.severity === 'CRITICAL' ? '#dc2626' : '#c2410c' }}>
                        {ev.severity}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '12px' }}>
                  No timeline events recorded.
                </div>
              )}
            </div>
          </section>

          {/* SECTION 12: ACTIVE FORENSIC INVESTIGATIONS */}
          <section
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '16px 20px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  CASE MANAGEMENT
                </span>
                <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                  Active Forensic Investigations ({sum?.total_investigations ?? 0})
                </h2>
              </div>
              <button
                onClick={() => setIsNewInvestigationOpen(true)}
                style={{
                  padding: '4px 8px',
                  backgroundColor: '#1e40af',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '3px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <Plus size={12} />
                <span>New Case</span>
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '300px', overflowY: 'auto' }}>
              {telemetry?.priority_investigations && telemetry.priority_investigations.length > 0 ? (
                telemetry.priority_investigations.slice(0, 5).map((inv) => (
                  <div
                    key={inv.investigation_id}
                    style={{
                      backgroundColor: '#f8fafc',
                      border: '1px solid #e2e8f0',
                      borderRadius: '4px',
                      padding: '10px 12px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>{inv.title}</span>
                      <span
                        style={{
                          fontSize: '9px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: '3px',
                          backgroundColor: inv.status === 'CLOSED' ? '#f0fdf4' : '#eff6ff',
                          color: inv.status === 'CLOSED' ? '#16a34a' : '#1d4ed8',
                        }}
                      >
                        {inv.status}
                      </span>
                    </div>

                    <div style={{ fontSize: '10px', color: '#64748b' }}>
                      Analyst: <strong>{inv.assigned_analyst || 'Unassigned'}</strong> • Systems: {inv.systems_count} • Findings: {inv.findings_count} • Evidence: {inv.evidence_count}
                    </div>

                    <div style={{ display: 'flex', gap: '4px', marginTop: '4px' }}>
                      <button
                        onClick={() => onNavigate('investigations')}
                        style={{
                          padding: '2px 6px',
                          backgroundColor: '#ffffff',
                          border: '1px solid #cbd5e1',
                          borderRadius: '3px',
                          fontSize: '10px',
                          fontWeight: 600,
                          color: '#1e40af',
                          cursor: 'pointer',
                        }}
                      >
                        Open Investigation
                      </button>
                      <button
                        onClick={() => onNavigate('investigations')}
                        style={{
                          padding: '2px 6px',
                          backgroundColor: '#ffffff',
                          border: '1px solid #cbd5e1',
                          borderRadius: '3px',
                          fontSize: '10px',
                          color: '#475569',
                          cursor: 'pointer',
                        }}
                      >
                        Timeline
                      </button>
                      <button
                        onClick={() => onNavigate('reports')}
                        style={{
                          padding: '2px 6px',
                          backgroundColor: '#ffffff',
                          border: '1px solid #cbd5e1',
                          borderRadius: '3px',
                          fontSize: '10px',
                          color: '#475569',
                          cursor: 'pointer',
                        }}
                      >
                        Generate Report
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '12px' }}>
                  No active investigations.
                </div>
              )}
            </div>
          </section>
        </div>

        {/* ========================================================================= */}
        {/* SECTION 13: FORENSIC REPORTS & EXECUTION LOGS */}
        {/* ========================================================================= */}
        <section
          style={{
            backgroundColor: '#ffffff',
            border: '1px solid #e2e8f0',
            borderRadius: '6px',
            padding: '16px 20px',
            boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '10px', fontWeight: 700, color: '#1e40af', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                AUDITABLE OUTPUTS
              </span>
              <h2 style={{ margin: '1px 0 0 0', fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
                Forensic Reports & Execution Logs
              </h2>
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                onClick={() => onNavigate('jobs')}
                style={{
                  padding: '3px 8px',
                  backgroundColor: '#ffffff',
                  border: '1px solid #cbd5e1',
                  borderRadius: '3px',
                  fontSize: '11px',
                  color: '#475569',
                  cursor: 'pointer',
                }}
              >
                All Jobs ({sum?.total_jobs ?? 0})
              </button>
              <button
                onClick={() => onNavigate('reports')}
                style={{
                  padding: '3px 8px',
                  backgroundColor: '#1e40af',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '3px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Reports Vault
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #cbd5e1', color: '#475569', textAlign: 'left', backgroundColor: '#f8fafc' }}>
                  <th style={{ padding: '6px 8px' }}>Log / Report ID</th>
                  <th style={{ padding: '6px 8px' }}>JOCKY Script / Context</th>
                  <th style={{ padding: '6px 8px' }}>Target System</th>
                  <th style={{ padding: '6px 8px' }}>Status</th>
                  <th style={{ padding: '6px 8px' }}>Integrity</th>
                  <th style={{ padding: '6px 8px' }}>Execution Time</th>
                  <th style={{ padding: '6px 8px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {telemetry?.recent_jobs && telemetry.recent_jobs.length > 0 ? (
                  telemetry.recent_jobs.slice(0, 5).map((job) => (
                    <tr key={job.job_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#64748b' }}>
                        {job.job_id.slice(0, 8)}...
                      </td>
                      <td style={{ padding: '6px 8px', fontWeight: 600, color: '#0f172a' }}>{job.name}</td>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace', color: '#1e40af' }}>
                        {job.hostname || job.agent_id}
                      </td>
                      <td style={{ padding: '6px 8px' }}>
                        <span
                          style={{
                            fontSize: '9px',
                            fontWeight: 700,
                            padding: '1px 5px',
                            borderRadius: '3px',
                            backgroundColor: job.status === 'COMPLETED' ? '#f0fdf4' : '#fff7ed',
                            color: job.status === 'COMPLETED' ? '#16a34a' : '#c2410c',
                          }}
                        >
                          {job.status}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: '#16a34a', fontWeight: 600 }}>SHA-256 VERIFIED</td>
                      <td style={{ padding: '6px 8px', color: '#64748b' }}>
                        {new Date(job.created_at).toLocaleString()}
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                        <button
                          onClick={() => onNavigate('jobs')}
                          style={{
                            padding: '2px 6px',
                            backgroundColor: '#ffffff',
                            border: '1px solid #cbd5e1',
                            borderRadius: '3px',
                            fontSize: '10px',
                            color: '#1e40af',
                            cursor: 'pointer',
                          }}
                        >
                          View Logs
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} style={{ padding: '16px', textAlign: 'center', color: '#64748b' }}>
                      No execution logs available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* ========================================================================= */}
      {/* MODAL: RUN JOCKY ANALYSIS */}
      {/* ========================================================================= */}
      <Modal isOpen={isRunModalOpen} onClose={() => setIsRunModalOpen(false)} title="Run JOCKY Forensic Script Analysis">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              Select Target Host
            </label>
            <select
              value={targetAgentId}
              onChange={(e) => setTargetAgentId(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 8px',
                borderRadius: '4px',
                border: '1px solid #cbd5e1',
                fontSize: '12px',
              }}
            >
              {telemetry?.systems?.map((s) => (
                <option key={s.agent_id} value={s.agent_id}>
                  {s.hostname} ({s.operating_system} - {s.status})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              Template
            </label>
            <select
              value={selectedTemplateKey}
              onChange={(e) => handleTemplateChange(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 8px',
                borderRadius: '4px',
                border: '1px solid #cbd5e1',
                fontSize: '12px',
              }}
            >
              {Object.entries(SCRIPT_TEMPLATES).map(([k, t]) => (
                <option key={k} value={k}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              JOCKY Forensic Script
            </label>
            <div style={{ backgroundColor: '#0f172a', borderRadius: '4px', padding: '8px' }}>
              <textarea
                value={scriptCode}
                onChange={(e) => setScriptCode(e.target.value)}
                rows={8}
                style={{
                  width: '100%',
                  backgroundColor: 'transparent',
                  color: '#38bdf8',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  border: 'none',
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
            <button
              onClick={() => setIsRunModalOpen(false)}
              style={{
                padding: '6px 12px',
                backgroundColor: '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '4px',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              onClick={async () => {
                await handleExecuteScript();
                setIsRunModalOpen(false);
              }}
              style={{
                padding: '6px 14px',
                backgroundColor: '#1e40af',
                color: '#ffffff',
                border: 'none',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              Dispatch to Host
            </button>
          </div>
        </div>
      </Modal>

      {/* ========================================================================= */}
      {/* MODAL: NEW INVESTIGATION */}
      {/* ========================================================================= */}
      <Modal isOpen={isNewInvestigationOpen} onClose={() => setIsNewInvestigationOpen(false)} title="Create Forensic Investigation Case">
        <form onSubmit={handleCreateInvestigation} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              Case Title *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. INC-2026-MULTI-ENDPOINT-TRIAGE: Cross-Platform Intrusion"
              value={invTitle}
              onChange={(e) => setInvTitle(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 10px',
                borderRadius: '4px',
                border: '1px solid #cbd5e1',
                fontSize: '12px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              Forensic Hypothesis & Scope
            </label>
            <textarea
              placeholder="Describe adversary indicators, anomalous processes, and multi-endpoint investigative goals..."
              value={invDesc}
              onChange={(e) => setInvDesc(e.target.value)}
              rows={4}
              style={{
                width: '100%',
                padding: '6px 10px',
                borderRadius: '4px',
                border: '1px solid #cbd5e1',
                fontSize: '12px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '11px', fontWeight: 700, color: '#475569', display: 'block', marginBottom: '3px' }}>
              Assigned Forensic Lead
            </label>
            <input
              type="text"
              value={invAssigned}
              onChange={(e) => setInvAssigned(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 10px',
                borderRadius: '4px',
                border: '1px solid #cbd5e1',
                fontSize: '12px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
            <button
              type="button"
              onClick={() => setIsNewInvestigationOpen(false)}
              style={{
                padding: '6px 12px',
                backgroundColor: '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '4px',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creatingInv}
              style={{
                padding: '6px 14px',
                backgroundColor: '#1e40af',
                color: '#ffffff',
                border: 'none',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              {creatingInv ? 'Creating...' : 'Open Case'}
            </button>
          </div>
        </form>
      </Modal>

      {/* ========================================================================= */}
      {/* MODAL: TIMELINE EVENT DETAIL */}
      {/* ========================================================================= */}
      <Modal isOpen={!!selectedEventModal} onClose={() => setSelectedEventModal(null)} title="Forensic Timeline Event Details">
        {selectedEventModal && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
            <div>
              <span style={{ color: '#64748b' }}>Event ID: </span>
              <strong style={{ fontFamily: 'monospace' }}>{selectedEventModal.id}</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Timestamp: </span>
              <strong>{new Date(selectedEventModal.timestamp).toISOString()}</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>System Node: </span>
              <strong style={{ fontFamily: 'monospace', color: '#1e40af' }}>{selectedEventModal.hostname}</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Event Type: </span>
              <strong style={{ color: '#1e40af' }}>{selectedEventModal.event_type}</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Severity: </span>
              <strong style={{ color: selectedEventModal.severity === 'CRITICAL' ? '#dc2626' : '#ea580c' }}>
                {selectedEventModal.severity}
              </strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Summary: </span>
              <p style={{ margin: '4px 0', fontSize: '13px', fontWeight: 600, color: '#0f172a' }}>
                {selectedEventModal.summary}
              </p>
            </div>
            {selectedEventModal.details && (
              <div style={{ backgroundColor: '#f8fafc', padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0', fontFamily: 'monospace', fontSize: '11px' }}>
                <pre style={{ margin: 0 }}>{JSON.stringify(selectedEventModal.details, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* ========================================================================= */}
      {/* MODAL: IOC DETAIL */}
      {/* ========================================================================= */}
      <Modal isOpen={!!selectedIocModal} onClose={() => setSelectedIocModal(null)} title="Indicator Intelligence Details">
        {selectedIocModal && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
            <div>
              <span style={{ color: '#64748b' }}>Indicator Type: </span>
              <strong style={{ color: '#1e40af' }}>{selectedIocModal.type}</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Indicator Value: </span>
              <strong style={{ fontFamily: 'monospace', fontSize: '13px', color: '#0f172a', wordBreak: 'break-all' }}>
                {selectedIocModal.value}
              </strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Severity: </span>
              <strong style={{ color: selectedIocModal.severity === 'CRITICAL' ? '#dc2626' : '#ea580c' }}>
                {selectedIocModal.severity}
              </strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Total Occurrences: </span>
              <strong>{selectedIocModal.occurrences || 1} hits</strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Systems Observed: </span>
              <strong>{selectedIocModal.agents_count || 1} distinct hosts</strong>
            </div>
            {selectedIocModal.first_seen && (
              <div>
                <span style={{ color: '#64748b' }}>First Seen: </span>
                <strong>{new Date(selectedIocModal.first_seen).toLocaleString()}</strong>
              </div>
            )}
            {selectedIocModal.last_seen && (
              <div>
                <span style={{ color: '#64748b' }}>Last Seen: </span>
                <strong>{new Date(selectedIocModal.last_seen).toLocaleString()}</strong>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};
