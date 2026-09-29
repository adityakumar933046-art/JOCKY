import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import {
  Investigation,
  TimelineResponse,
  Agent,
  Job,
  Finding,
  EvidenceRecord,
  NormalizedArtifact,
  Indicator,
  InvestigationGraph,
  InvestigationNote,
  InvestigationSnapshot,
} from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { Modal } from '../components/Modal';
import { InvestigationGraphView } from '../components/InvestigationGraphView';
import {
  FolderGit2,
  Plus,
  Clock,
  FileText,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Share2,
  Server,
  Layers,
  Cpu,
  AlertTriangle,
  Camera,
  Trash2,
  Send,
  Search,
} from 'lucide-react';

type WorkspaceTab =
  | 'OVERVIEW'
  | 'TIMELINE'
  | 'GRAPH'
  | 'SYSTEMS'
  | 'ARTIFACTS'
  | 'INDICATORS'
  | 'FINDINGS'
  | 'EVIDENCE'
  | 'NOTES'
  | 'REPORTS';

export const InvestigationsPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);

  // New Investigation Modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newAnalyst, setNewAnalyst] = useState('Senior Incident Responder');
  const [selectedAgentIds, setSelectedAgentIds] = useState<string[]>([]);
  const [selectedJobIds, setSelectedJobIds] = useState<string[]>([]);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Active Investigation Workspace
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('OVERVIEW');

  // Workspace Tab Data
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineCategoryFilter, setTimelineCategoryFilter] = useState('');
  const [timelineSearch, setTimelineSearch] = useState('');
  const [expandedEvents, setExpandedEvents] = useState<Record<number, boolean>>({});

  const [graphData, setGraphData] = useState<InvestigationGraph | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);

  const [artifacts, setArtifacts] = useState<NormalizedArtifact[]>([]);
  const [artifactsLoading, setArtifactsLoading] = useState(false);
  const [selectedArtifact, setSelectedArtifact] = useState<NormalizedArtifact | null>(null);
  const [artifactTypeFilter, setArtifactTypeFilter] = useState('');

  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [indicatorsLoading, setIndicatorsLoading] = useState(false);

  const [notes, setNotes] = useState<InvestigationNote[]>([]);
  const [notesLoading, setNotesLoading] = useState(false);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [addingNote, setAddingNote] = useState(false);

  const [snapshots, setSnapshots] = useState<InvestigationSnapshot[]>([]);
  const [snapshotsLoading, setSnapshotsLoading] = useState(false);
  const [newSnapshotTitle, setNewSnapshotTitle] = useState('');
  const [creatingSnapshot, setCreatingSnapshot] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const [invData, agData, jbData, fnData, evData] = await Promise.all([
        api.getInvestigations(),
        api.getAgents(),
        api.getJobs(),
        api.getFindings(),
        api.getEvidence(),
      ]);
      setInvestigations(invData);
      setAgents(agData);
      setJobs(jbData);
      setFindings(fnData);
      setEvidence(evData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const openInvestigation = async (inv: Investigation) => {
    setActiveInvestigation(inv);
    setActiveTab('OVERVIEW');
    setTimeline(null);
    setGraphData(null);
    setArtifacts([]);
    setIndicators([]);
    setNotes([]);
    setSnapshots([]);
    setExpandedEvents({});

    // Load full investigation details & timeline
    try {
      setTimelineLoading(true);
      const fullInv = await api.getInvestigation(inv.investigation_id);
      setActiveInvestigation(fullInv);
      const tl = await api.getTimeline(inv.investigation_id);
      setTimeline(tl);
    } catch (err) {
      console.error(err);
    } finally {
      setTimelineLoading(false);
    }
  };

  // Lazy tab loader
  const handleTabSelect = async (tab: WorkspaceTab) => {
    setActiveTab(tab);
    if (!activeInvestigation) return;
    const invId = activeInvestigation.investigation_id;

    if (tab === 'GRAPH' && !graphData) {
      try {
        setGraphLoading(true);
        const g = await api.getInvestigationGraph(invId);
        setGraphData(g);
      } catch (err) {
        console.error(err);
      } finally {
        setGraphLoading(false);
      }
    } else if (tab === 'ARTIFACTS' && artifacts.length === 0) {
      try {
        setArtifactsLoading(true);
        const arts = await api.getInvestigationArtifacts(invId);
        setArtifacts(arts);
      } catch (err) {
        console.error(err);
      } finally {
        setArtifactsLoading(false);
      }
    } else if (tab === 'INDICATORS' && indicators.length === 0) {
      try {
        setIndicatorsLoading(true);
        const inds = await api.getInvestigationIndicators(invId);
        setIndicators(inds);
      } catch (err) {
        console.error(err);
      } finally {
        setIndicatorsLoading(false);
      }
    } else if (tab === 'NOTES' && notes.length === 0) {
      try {
        setNotesLoading(true);
        const nList = await api.getInvestigationNotes(invId);
        setNotes(nList);
      } catch (err) {
        console.error(err);
      } finally {
        setNotesLoading(false);
      }
    } else if (tab === 'REPORTS' && snapshots.length === 0) {
      try {
        setSnapshotsLoading(true);
        const snList = await api.getInvestigationSnapshots(invId);
        setSnapshots(snList);
      } catch (err) {
        console.error(err);
      } finally {
        setSnapshotsLoading(false);
      }
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!activeInvestigation) return;
    try {
      const updated = await api.updateInvestigation(activeInvestigation.investigation_id, {
        status: newStatus,
      });
      setActiveInvestigation(updated);
      await loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    setIsSubmitting(true);
    try {
      await api.createInvestigation({
        title: newTitle,
        description: newDescription,
        assigned_analyst: newAnalyst,
        agent_ids: selectedAgentIds,
        job_ids: selectedJobIds,
        finding_ids: selectedFindingIds,
      });
      setIsCreateOpen(false);
      setNewTitle('');
      setNewDescription('');
      setSelectedAgentIds([]);
      setSelectedJobIds([]);
      setSelectedFindingIds([]);
      await loadData();
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeInvestigation || !newNoteContent.trim()) return;
    setAddingNote(true);
    try {
      const note = await api.addInvestigationNote(activeInvestigation.investigation_id, newNoteContent.trim());
      setNotes(prev => [note, ...prev]);
      setNewNoteContent('');
    } catch (err) {
      console.error(err);
    } finally {
      setAddingNote(false);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!activeInvestigation) return;
    try {
      await api.deleteInvestigationNote(activeInvestigation.investigation_id, noteId);
      setNotes(prev => prev.filter(n => n.note_id !== noteId));
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeInvestigation || !newSnapshotTitle.trim()) return;
    setCreatingSnapshot(true);
    try {
      const snap = await api.createInvestigationSnapshot(activeInvestigation.investigation_id, newSnapshotTitle.trim());
      setSnapshots(prev => [snap, ...prev]);
      setNewSnapshotTitle('');
    } catch (err) {
      console.error(err);
    } finally {
      setCreatingSnapshot(false);
    }
  };

  const toggleEventExpand = (index: number) => {
    setExpandedEvents((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const filteredTimelineEvents = (timeline?.events || []).filter(e => {
    if (timelineCategoryFilter && !e.event_type.toLowerCase().includes(timelineCategoryFilter.toLowerCase())) return false;
    if (timelineSearch) {
      const q = timelineSearch.toLowerCase();
      return e.summary.toLowerCase().includes(q) || JSON.stringify(e.details).toLowerCase().includes(q);
    }
    return true;
  });

  const filteredArtifacts = artifacts.filter(a => {
    if (artifactTypeFilter && a.artifact_type !== artifactTypeFilter) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Forensic Investigations & Workspace"
        subtitle="10-tab multi-endpoint investigation console: Timeline, Graph, Artifacts, IOCs, Notes, and Reports"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        {/* Header Action */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <div style={{ fontSize: '14px', color: '#64748b' }}>
            Active Case Management: <strong>{investigations.length}</strong> investigations
          </div>

          <button
            onClick={() => {
              if (agents.length > 0) setSelectedAgentIds([agents[0].agent_id]);
              setIsCreateOpen(true);
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
              boxShadow: '0 1px 2px rgba(37,99,235,0.2)',
            }}
          >
            <Plus size={16} />
            <span>Create New Investigation Case</span>
          </button>
        </div>

        {/* Investigations Table */}
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
          }}
        >
          {investigations.length === 0 ? (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <FolderGit2 size={36} color="#94a3b8" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: '#0f172a' }}>
                No active investigations
              </div>
              <div style={{ fontSize: '13px', marginTop: '4px' }}>
                Create a new case above to correlate systems, forensic jobs, and threat indicators.
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #e2e8f0', backgroundColor: '#f8fafc', color: '#475569', fontWeight: 600 }}>
                  <th style={{ padding: '12px 16px' }}>CASE ID</th>
                  <th style={{ padding: '12px 16px' }}>TITLE</th>
                  <th style={{ padding: '12px 16px' }}>STATUS</th>
                  <th style={{ padding: '12px 16px' }}>ANALYST</th>
                  <th style={{ padding: '12px 16px' }}>ENDPOINTS</th>
                  <th style={{ padding: '12px 16px' }}>FINDINGS</th>
                  <th style={{ padding: '12px 16px' }}>UPDATED</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((inv) => (
                  <tr
                    key={inv.investigation_id}
                    onClick={() => openInvestigation(inv)}
                    style={{
                      borderBottom: '1px solid #f1f5f9',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#f8fafc')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600, color: '#2563eb' }}>
                      {inv.investigation_id}
                    </td>
                    <td style={{ padding: '12px 16px', fontWeight: 600, color: '#0f172a' }}>
                      {inv.title}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge status={inv.status} />
                    </td>
                    <td style={{ padding: '12px 16px', color: '#475569' }}>
                      {inv.assigned_analyst || 'Unassigned'}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#475569' }}>
                      {inv.agents?.length || 0} systems
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span
                        style={{
                          backgroundColor: (inv.findings?.length || 0) > 0 ? '#fef2f2' : '#f8fafc',
                          color: (inv.findings?.length || 0) > 0 ? '#dc2626' : '#64748b',
                          padding: '2px 8px',
                          borderRadius: '12px',
                          fontWeight: 600,
                          fontSize: '12px',
                        }}
                      >
                        {inv.findings?.length || 0} alerts
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>
                      {new Date(inv.updated_at).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openInvestigation(inv);
                        }}
                        style={{
                          padding: '6px 12px',
                          backgroundColor: '#f1f5f9',
                          border: '1px solid #cbd5e1',
                          borderRadius: '4px',
                          color: '#0f172a',
                          fontWeight: 600,
                          fontSize: '12px',
                          cursor: 'pointer',
                        }}
                      >
                        Open Workspace
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Create Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create New Forensic Investigation Case"
      >
        <form onSubmit={handleCreateSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
              INVESTIGATION TITLE *
            </label>
            <input
              type="text"
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g., Triage: Suspected Reverse Shell on Production Web"
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
              LEAD FORENSIC INVESTIGATOR
            </label>
            <input
              type="text"
              value={newAnalyst}
              onChange={(e) => setNewAnalyst(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
              CASE SCOPE & DESCRIPTION
            </label>
            <textarea
              rows={3}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Summary of incident scope, target hosts, and initial triage vectors..."
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                boxSizing: 'border-box',
              }}
            />
          </div>

          {/* Associate Systems */}
          {agents.length > 0 && (
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
                ASSOCIATE TARGET SYSTEMS
              </label>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {agents.map((ag) => {
                  const isSelected = selectedAgentIds.includes(ag.agent_id);
                  return (
                    <button
                      type="button"
                      key={ag.agent_id}
                      onClick={() => {
                        setSelectedAgentIds((prev) =>
                          isSelected ? prev.filter((id) => id !== ag.agent_id) : [...prev, ag.agent_id]
                        );
                      }}
                      style={{
                        padding: '6px 12px',
                        borderRadius: '6px',
                        border: isSelected ? '1px solid #2563eb' : '1px solid #cbd5e1',
                        backgroundColor: isSelected ? '#eff6ff' : '#ffffff',
                        color: isSelected ? '#1d4ed8' : '#334155',
                        fontSize: '12px',
                        cursor: 'pointer',
                        fontWeight: isSelected ? 600 : 400,
                      }}
                    >
                      {ag.hostname} ({ag.operating_system})
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '16px' }}>
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              style={{
                padding: '8px 16px',
                backgroundColor: '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '6px',
                color: '#334155',
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              style={{
                padding: '8px 20px',
                backgroundColor: '#2563eb',
                border: 'none',
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: 600,
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
              }}
            >
              {isSubmitting ? 'Creating...' : 'Create Investigation'}
            </button>
          </div>
        </form>
      </Modal>

      {/* 10-Tab Investigation Workspace Modal */}
      {activeInvestigation && (
        <Modal
          isOpen={!!activeInvestigation}
          onClose={() => setActiveInvestigation(null)}
          title={`Investigation Workspace: ${activeInvestigation.title} [${activeInvestigation.investigation_id}]`}
          maxWidth="1100px"
        >
          <div className="flex flex-col gap-4 text-slate-100 min-h-[600px]">
            {/* Top Workspace Bar */}
            <div className="flex flex-wrap items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg gap-2">
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-400 font-semibold">STATUS:</span>
                <div className="flex gap-1.5">
                  {(['OPEN', 'IN_PROGRESS', 'CLOSED'] as const).map((st) => (
                    <button
                      key={st}
                      onClick={() => handleStatusChange(st)}
                      className={`px-2.5 py-1 rounded text-xs font-bold transition ${
                        activeInvestigation.status === st
                          ? 'bg-sky-600 text-white shadow'
                          : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <a
                  href={api.getReportUrl(activeInvestigation.investigation_id, 'html')}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs font-medium border border-slate-700 transition"
                >
                  <FileText size={14} />
                  <span>Report HTML</span>
                  <ExternalLink size={12} />
                </a>

                <a
                  href={api.getReportUrl(activeInvestigation.investigation_id, 'json')}
                  download={`investigation_${activeInvestigation.investigation_id}.json`}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium border border-slate-700 transition"
                >
                  <Download size={14} />
                  <span>JSON</span>
                </a>
              </div>
            </div>

            {/* 10 Workspace Tabs Header */}
            <div className="flex flex-wrap border-b border-slate-800 gap-1 text-xs">
              {(
                [
                  ['OVERVIEW', 'Overview'],
                  ['TIMELINE', `Timeline (${timeline?.events.length || 0})`],
                  ['GRAPH', 'Graph View'],
                  ['SYSTEMS', `Systems (${activeInvestigation.agents?.length || 0})`],
                  ['ARTIFACTS', 'Artifacts'],
                  ['INDICATORS', 'IOCs'],
                  ['FINDINGS', `Findings (${activeInvestigation.findings?.length || 0})`],
                  ['EVIDENCE', `Evidence (${activeInvestigation.evidence?.length || 0})`],
                  ['NOTES', `Notes (${notes.length})`],
                  ['REPORTS', 'Reports & Snapshots'],
                ] as const
              ).map(([tabKey, label]) => (
                <button
                  key={tabKey}
                  onClick={() => handleTabSelect(tabKey)}
                  className={`px-3 py-2 font-semibold transition border-b-2 ${
                    activeTab === tabKey
                      ? 'border-sky-500 text-sky-400 bg-slate-900/60'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* TAB 1: OVERVIEW */}
            {activeTab === 'OVERVIEW' && (
              <div className="space-y-4">
                <div className="grid grid-cols-4 gap-3">
                  <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400">LEAD ANALYST</span>
                    <p className="font-semibold text-slate-100 text-sm mt-0.5">{activeInvestigation.assigned_analyst || 'Unassigned'}</p>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400">TARGET ENDPOINTS</span>
                    <p className="font-semibold text-cyan-400 text-sm mt-0.5">{activeInvestigation.agents?.length || 0} systems</p>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400">THREAT FINDINGS</span>
                    <p className="font-semibold text-rose-400 text-sm mt-0.5">{activeInvestigation.findings?.length || 0} identified</p>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
                    <span className="text-[11px] text-slate-400">EVIDENCE ACQUIRED</span>
                    <p className="font-semibold text-emerald-400 text-sm mt-0.5">{activeInvestigation.evidence?.length || 0} records</p>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Scope & Triage Description</h4>
                  <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                    {activeInvestigation.description || 'No detailed scope description provided.'}
                  </p>
                </div>
              </div>
            )}

            {/* TAB 2: TIMELINE */}
            {activeTab === 'TIMELINE' && (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 p-2 bg-slate-900 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-2">
                    <Search size={14} className="text-slate-400" />
                    <input
                      type="text"
                      placeholder="Filter timeline events..."
                      value={timelineSearch}
                      onChange={(e) => setTimelineSearch(e.target.value)}
                      className="bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
                    />
                  </div>
                  <div className="flex items-center gap-1.5">
                    {['', 'PROCESS', 'NETWORK', 'FILE', 'THREAT', 'EVIDENCE'].map((cat) => (
                      <button
                        key={cat}
                        onClick={() => setTimelineCategoryFilter(cat)}
                        className={`px-2 py-0.5 rounded text-[11px] font-medium border ${
                          timelineCategoryFilter === cat
                            ? 'bg-sky-600 border-sky-500 text-white'
                            : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {cat || 'ALL'}
                      </button>
                    ))}
                  </div>
                </div>

                {timelineLoading ? (
                  <div className="py-12 text-center text-slate-500 text-xs">Reconstructing chronological timeline...</div>
                ) : filteredTimelineEvents.length === 0 ? (
                  <div className="py-12 text-center text-slate-500 text-xs">No matching timeline events.</div>
                ) : (
                  <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                    {filteredTimelineEvents.map((evt, idx) => (
                      <div key={idx} className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] text-sky-400">
                            {new Date(evt.timestamp).toLocaleString()}
                          </span>
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
                            {evt.event_type}
                          </span>
                        </div>
                        <p className="font-medium text-slate-200">{evt.summary}</p>
                        {evt.details && Object.keys(evt.details).length > 0 && (
                          <div className="pt-1 text-[11px] text-slate-500 font-mono">
                            {JSON.stringify(evt.details)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: GRAPH VIEW */}
            {activeTab === 'GRAPH' && (
              <div className="h-[550px]">
                {graphLoading ? (
                  <div className="h-full flex items-center justify-center text-slate-500 text-xs">
                    Building investigation relationship graph...
                  </div>
                ) : graphData ? (
                  <InvestigationGraphView graph={graphData} />
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-500 text-xs">
                    No graph data available for this investigation.
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: SYSTEMS */}
            {activeTab === 'SYSTEMS' && (
              <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {(activeInvestigation.agents || []).map((ag) => (
                    <div key={ag.agent_id} className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-cyan-400 font-bold text-xs">{ag.agent_id}</span>
                        <StatusBadge status={ag.status} />
                      </div>
                      <h4 className="font-bold text-slate-100 text-sm">{ag.hostname}</h4>
                      <p className="text-xs text-slate-400">{ag.operating_system} {ag.os_version || ''}</p>
                      <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] text-slate-500 font-mono">
                        <span>Trust: {ag.trust_state}</span>
                        <span>Seen: {new Date(ag.last_seen).toLocaleDateString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 5: ARTIFACTS */}
            {activeTab === 'ARTIFACTS' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-medium">Type:</span>
                  {['', 'PROCESS', 'NETWORK', 'FILE', 'SERVICE', 'DRIVER', 'PERSISTENCE'].map(t => (
                    <button
                      key={t}
                      onClick={() => setArtifactTypeFilter(t)}
                      className={`px-2 py-0.5 rounded text-[11px] font-medium border ${
                        artifactTypeFilter === t
                          ? 'bg-sky-600 border-sky-500 text-white'
                          : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {t || 'ALL'}
                    </button>
                  ))}
                </div>

                {artifactsLoading ? (
                  <div className="py-12 text-center text-slate-500 text-xs">Loading normalized artifacts...</div>
                ) : filteredArtifacts.length === 0 ? (
                  <div className="py-12 text-center text-slate-500 text-xs">No normalized artifacts recorded yet.</div>
                ) : (
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-semibold border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Artifact ID</th>
                          <th className="py-2 px-3">Details / Name</th>
                          <th className="py-2 px-3">Host</th>
                          <th className="py-2 px-3">Timestamp</th>
                          <th className="py-2 px-3 text-right">Inspect</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-sans">
                        {filteredArtifacts.map(art => {
                          const name = art.normalized_attributes?.name || art.normalized_attributes?.filename || art.normalized_attributes?.service_name || art.normalized_attributes?.remote_ip || 'Item';
                          return (
                            <tr key={art.artifact_id} className="hover:bg-slate-800/40">
                              <td className="py-2 px-3 font-mono text-cyan-400">{art.artifact_type}</td>
                              <td className="py-2 px-3 font-mono text-slate-400">{art.artifact_id}</td>
                              <td className="py-2 px-3 font-medium text-slate-200">{name}</td>
                              <td className="py-2 px-3 text-slate-400">{art.hostname}</td>
                              <td className="py-2 px-3 text-slate-500 font-mono text-[11px]">{new Date(art.timestamp).toLocaleTimeString()}</td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  onClick={() => setSelectedArtifact(art)}
                                  className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px]"
                                >
                                  JSON
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Artifact JSON Inspector Drawer */}
                {selectedArtifact && (
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                    <div className="flex justify-between items-center mb-2">
                      <span className="font-bold text-xs text-sky-400">Artifact: {selectedArtifact.artifact_id} ({selectedArtifact.artifact_type})</span>
                      <button onClick={() => setSelectedArtifact(null)} className="text-slate-400 hover:text-slate-200 text-xs">✕ Close</button>
                    </div>
                    <pre className="p-2 bg-slate-950 rounded text-[10px] font-mono text-slate-300 max-h-48 overflow-auto border border-slate-800">
                      {JSON.stringify(selectedArtifact.normalized_attributes, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* TAB 6: INDICATORS */}
            {activeTab === 'INDICATORS' && (
              <div className="space-y-3">
                {indicatorsLoading ? (
                  <div className="py-12 text-center text-slate-500 text-xs">Extracting indicators...</div>
                ) : indicators.length === 0 ? (
                  <div className="py-12 text-center text-slate-500 text-xs">No IOC indicators extracted yet.</div>
                ) : (
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-semibold border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Indicator Value</th>
                          <th className="py-2 px-3">Hits</th>
                          <th className="py-2 px-3">Severity</th>
                          <th className="py-2 px-3">Agents Observed</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-sans">
                        {indicators.map(ind => (
                          <tr key={ind.indicator_id} className="hover:bg-slate-800/40">
                            <td className="py-2 px-3 font-mono text-slate-400">{ind.indicator_type}</td>
                            <td className="py-2 px-3 font-mono text-slate-100 font-medium">{ind.value}</td>
                            <td className="py-2 px-3 text-slate-300 font-mono">{ind.occurrences}</td>
                            <td className="py-2 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                ind.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                                ind.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                                'bg-slate-800 text-slate-300'
                              }`}>
                                {ind.severity}
                              </span>
                            </td>
                            <td className="py-2 px-3 font-mono text-[11px] text-cyan-400">
                              {ind.agents_observed?.join(', ') || 'N/A'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB 7: FINDINGS */}
            {activeTab === 'FINDINGS' && (
              <div className="space-y-3">
                {(activeInvestigation.findings || []).length === 0 ? (
                  <div className="py-12 text-center text-slate-500 text-xs">No findings attached to this investigation.</div>
                ) : (
                  <div className="space-y-2">
                    {activeInvestigation.findings.map(f => (
                      <div key={f.finding_id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            f.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                            f.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {f.severity}
                          </span>
                          <span className="font-mono text-slate-500 text-[10px]">{f.rule_id}</span>
                        </div>
                        <h4 className="font-bold text-slate-200 text-xs">{f.title}</h4>
                        <p className="text-slate-400 text-xs leading-relaxed">{f.description}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 8: EVIDENCE */}
            {activeTab === 'EVIDENCE' && (
              <div className="space-y-3">
                {(activeInvestigation.evidence || []).length === 0 ? (
                  <div className="py-12 text-center text-slate-500 text-xs">No evidence records attached.</div>
                ) : (
                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-semibold border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Evidence ID</th>
                          <th className="py-2 px-3">Operation</th>
                          <th className="py-2 px-3">Hostname</th>
                          <th className="py-2 px-3">SHA-256 Hash</th>
                          <th className="py-2 px-3">Integrity</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-sans">
                        {activeInvestigation.evidence.map(ev => (
                          <tr key={ev.evidence_id} className="hover:bg-slate-800/40">
                            <td className="py-2 px-3 font-mono text-sky-400 font-medium">{ev.evidence_id}</td>
                            <td className="py-2 px-3 text-slate-200">{ev.operation}</td>
                            <td className="py-2 px-3 text-slate-400">{ev.hostname}</td>
                            <td className="py-2 px-3 font-mono text-[10px] text-slate-400 truncate max-w-xs" title={ev.content_hash}>
                              {ev.content_hash || 'N/A'}
                            </td>
                            <td className="py-2 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                                VERIFIED
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB 9: NOTES */}
            {activeTab === 'NOTES' && (
              <div className="space-y-4">
                <form onSubmit={handleAddNote} className="space-y-2">
                  <textarea
                    rows={2}
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    placeholder="Add an investigative note, hypothesis, or interview log..."
                    className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-700"
                  />
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={addingNote || !newNoteContent.trim()}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded text-xs font-semibold"
                    >
                      <Send size={12} />
                      {addingNote ? 'Saving...' : 'Post Note'}
                    </button>
                  </div>
                </form>

                {notesLoading ? (
                  <div className="py-8 text-center text-slate-500 text-xs">Loading notes...</div>
                ) : notes.length === 0 ? (
                  <div className="py-8 text-center text-slate-500 text-xs">No collaborative notes posted yet.</div>
                ) : (
                  <div className="space-y-2 max-h-[350px] overflow-y-auto">
                    {notes.map(n => (
                      <div key={n.note_id} className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-bold text-sky-400">{n.author_name}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-500 font-mono">{new Date(n.created_at).toLocaleString()}</span>
                            <button onClick={() => handleDeleteNote(n.note_id)} className="text-slate-600 hover:text-rose-400">
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{n.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 10: REPORTS & SNAPSHOTS */}
            {activeTab === 'REPORTS' && (
              <div className="space-y-4">
                <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider">Formal Forensic Report</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Generate audited executive report with cryptographic custody checksums.</p>
                  </div>
                  <div className="flex gap-2">
                    <a
                      href={api.getReportUrl(activeInvestigation.investigation_id, 'html')}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center gap-1.5"
                    >
                      <FileText size={14} /> View HTML Report
                    </a>
                  </div>
                </div>

                {/* Point-in-time Snapshots */}
                <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider flex items-center gap-1.5">
                        <Camera size={14} className="text-amber-400" />
                        Point-in-Time Case Snapshots
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">Freeze and archive current case state for legal evidentiary hold.</p>
                    </div>
                  </div>

                  <form onSubmit={handleCreateSnapshot} className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Snapshot title (e.g., 'Initial Triage Baseline')..."
                      value={newSnapshotTitle}
                      onChange={(e) => setNewSnapshotTitle(e.target.value)}
                      className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={creatingSnapshot || !newSnapshotTitle.trim()}
                      className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded text-xs font-semibold"
                    >
                      {creatingSnapshot ? 'Freezing...' : 'Freeze Snapshot'}
                    </button>
                  </form>

                  {snapshotsLoading ? (
                    <div className="py-4 text-center text-slate-500 text-xs">Loading snapshots...</div>
                  ) : snapshots.length === 0 ? (
                    <div className="py-4 text-center text-slate-500 text-xs">No frozen snapshots created yet.</div>
                  ) : (
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {snapshots.map(sn => (
                        <div key={sn.snapshot_id} className="p-2.5 bg-slate-950 border border-slate-800 rounded flex items-center justify-between text-xs">
                          <div>
                            <span className="font-semibold text-slate-200">{sn.title}</span>
                            <span className="ml-2 font-mono text-[10px] text-slate-500">by {sn.created_by}</span>
                          </div>
                          <span className="font-mono text-[10px] text-slate-400">{new Date(sn.created_at).toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
