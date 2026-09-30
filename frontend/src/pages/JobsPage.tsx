import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Agent, Job, CompilerValidationResponse } from '../types/api';
import { StatusBadge } from '../components/StatusBadge';
import { Header } from '../components/Header';
import { Modal } from '../components/Modal';
import {
  PlaySquare,
  Plus,
  CheckCircle2,
  AlertCircle,
  Code2,
  Send,
  Eye,
} from 'lucide-react';

const TEMPLATES: Record<string, string> = {
  'Complete Threat Assessment': `# Complete forensic scan & threat assessment with extended JOCKY IR
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

  'Full Endpoint Triage': `# Comprehensive forensic scan & threat detection
SYSTEM INFO
SCAN PROCESSES
SCAN NETWORK
SCAN DRIVERS
SCAN SERVICES
SCAN FILES
ANALYZE PERSISTENCE
ANALYZE MEMORY
REPORT "endpoint_full_triage"`,

  'Quick Triage': `# Rapid forensic triage
SYSTEM INFO
SCAN PROCESSES
SCAN NETWORK
ANALYZE PERSISTENCE
REPORT "quick_triage_report"`,

  'Persistence & Sockets': `# Persistence and network triage
SCAN NETWORK
ANALYZE PERSISTENCE
REPORT "network_persist_report"`,

  'Network Audit': `# Network connections and sockets triage
SCAN NETWORK
ANALYZE NETWORK
REPORT "network_audit_report"`,

  'Memory & Process Audit': `# Memory and process inspection
SCAN PROCESSES
ANALYZE MEMORY
REPORT "proc_mem_report"`,
};

export const JobsPage: React.FC = () => {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterAgent, setFilterAgent] = useState<string>('');

  // Create Job Modal state
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [jobName, setJobName] = useState('');
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [detectionEnabled, setDetectionEnabled] = useState(true);
  const [jockySource, setJockySource] = useState(TEMPLATES['Full Endpoint Triage']);
  const [selectedTemplate, setSelectedTemplate] = useState('Full Endpoint Triage');

  // Compiler Validation state
  const [validationResult, setValidationResult] = useState<CompilerValidationResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Job Submission state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Job Detail Modal state
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [jobsData, agentsData] = await Promise.all([
        api.getJobs({
          status: filterStatus || undefined,
          agent_id: filterAgent || undefined,
        }),
        api.getAgents(),
      ]);
      setJobs(jobsData);
      setAgents(agentsData);
      if (agentsData.length > 0 && !selectedAgentId) {
        setSelectedAgentId(agentsData[0].agent_id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [filterStatus, filterAgent]);

  const handleTemplateChange = (templateName: string) => {
    setSelectedTemplate(templateName);
    if (TEMPLATES[templateName]) {
      setJockySource(TEMPLATES[templateName]);
    }
    setValidationResult(null);
    setValidationError(null);
  };

  const handleValidate = async () => {
    setIsValidating(true);
    setValidationResult(null);
    setValidationError(null);
    try {
      const res = await api.validateJocky(jockySource);
      setValidationResult(res);
      if (!res.valid) {
        setValidationError(res.errors.join('; '));
      }
    } catch (err: any) {
      setValidationError(err.message || 'Validation request failed');
    } finally {
      setIsValidating(false);
    }
  };

  const handleSubmitJob = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!jobName.trim()) {
      setSubmitError('Please enter a job name');
      return;
    }
    if (!selectedAgentId) {
      setSubmitError('Please select a target agent');
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await api.createJob({
        name: jobName,
        agent_id: selectedAgentId,
        jocky_source: jockySource,
        detection_enabled: detectionEnabled,
      });
      setIsCreateOpen(false);
      setJobName('');
      setValidationResult(null);
      await loadData();
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to dispatch job');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Header
        title="Forensic Jobs Orchestration"
        subtitle="Compile, validate, dispatch and monitor forensic execution jobs across endpoints"
        onRefresh={loadData}
        loading={loading}
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px' }}>
        {/* Action & Filter Bar */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '20px',
            gap: '16px',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                backgroundColor: '#ffffff',
                color: '#334155',
              }}
            >
              <option value="">All Statuses</option>
              <option value="PENDING">PENDING</option>
              <option value="ASSIGNED">ASSIGNED</option>
              <option value="RUNNING">RUNNING</option>
              <option value="COMPLETED">COMPLETED</option>
              <option value="FAILED">FAILED</option>
            </select>

            <select
              value={filterAgent}
              onChange={(e) => setFilterAgent(e.target.value)}
              style={{
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                backgroundColor: '#ffffff',
                color: '#334155',
              }}
            >
              <option value="">All Systems</option>
              {agents.map((ag) => (
                <option key={ag.agent_id} value={ag.agent_id}>
                  {ag.hostname} ({ag.operating_system})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => {
              setJobName(`Forensic Triage - ${new Date().toLocaleTimeString()}`);
              setValidationResult(null);
              setValidationError(null);
              setSubmitError(null);
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
            <span>Dispatch New Forensic Job</span>
          </button>
        </div>

        {/* Jobs Table */}
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            overflow: 'hidden',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
          }}
        >
          {jobs.length === 0 ? (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <PlaySquare size={36} color="#94a3b8" style={{ marginBottom: '12px' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: '#0f172a' }}>No jobs found</div>
              <div style={{ fontSize: '13px', marginTop: '4px' }}>
                Dispatch a forensic job above to initiate remote data collection.
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left' }}>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Job Name</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Target System</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Threat Detection</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Created At</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Duration / Completed</th>
                  <th style={{ padding: '12px 16px', color: '#64748b', fontWeight: 600 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const targetAgent = agents.find((a) => a.agent_id === job.agent_id);
                  return (
                    <tr
                      key={job.job_id}
                      style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer' }}
                      onClick={() => setSelectedJob(job)}
                    >
                      <td style={{ padding: '12px 16px' }}>
                        <StatusBadge status={job.status} type="job" />
                      </td>
                      <td style={{ padding: '12px 16px', fontWeight: 600, color: '#0f172a' }}>{job.name}</td>
                      <td style={{ padding: '12px 16px', color: '#334155' }}>
                        {targetAgent ? targetAgent.hostname : job.agent_id.substring(0, 10) + '...'}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {job.detection_enabled ? (
                          <span
                            style={{
                              backgroundColor: '#f0fdf4',
                              color: '#16a34a',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              fontSize: '11px',
                              fontWeight: 600,
                              border: '1px solid #bbf7d0',
                            }}
                          >
                            Active
                          </span>
                        ) : (
                          <span style={{ color: '#94a3b8', fontSize: '11px' }}>Disabled</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', color: '#64748b' }}>
                        {new Date(job.created_at).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: '12px 16px', color: '#64748b' }}>
                        {job.completed_at ? new Date(job.completed_at).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedJob(job);
                          }}
                          style={{
                            padding: '4px 8px',
                            backgroundColor: '#f1f5f9',
                            border: '1px solid #cbd5e1',
                            borderRadius: '4px',
                            color: '#2563eb',
                            fontSize: '12px',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <Eye size={12} />
                          <span>View</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Create Job Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Dispatch Forensic Job"
        maxWidth="800px"
      >
        <form onSubmit={handleSubmitJob} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {submitError && (
            <div
              style={{
                padding: '10px 14px',
                backgroundColor: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: '6px',
                color: '#b91c1c',
                fontSize: '13px',
              }}
            >
              {submitError}
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
                JOB NAME
              </label>
              <input
                type="text"
                value={jobName}
                onChange={(e) => setJobName(e.target.value)}
                placeholder="e.g. Investigation Triage #104"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px',
                  boxSizing: 'border-box',
                }}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
                TARGET SYSTEM
              </label>
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px',
                  backgroundColor: '#ffffff',
                  boxSizing: 'border-box',
                }}
                required
              >
                {agents.map((ag) => (
                  <option key={ag.agent_id} value={ag.agent_id}>
                    {ag.hostname} ({ag.operating_system} - {ag.status})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <input
                type="checkbox"
                id="detectionToggle"
                checked={detectionEnabled}
                onChange={(e) => setDetectionEnabled(e.target.checked)}
                style={{ width: '16px', height: '16px', cursor: 'pointer' }}
              />
              <label
                htmlFor="detectionToggle"
                style={{ fontSize: '13px', fontWeight: 600, color: '#0f172a', cursor: 'pointer' }}
              >
                Run Step 3 Threat Detection Engine on Collected Evidence
              </label>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: '#64748b' }}>Template:</label>
              <select
                value={selectedTemplate}
                onChange={(e) => handleTemplateChange(e.target.value)}
                style={{
                  padding: '6px 10px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  fontSize: '12px',
                  backgroundColor: '#f8fafc',
                }}
              >
                {Object.keys(TEMPLATES).map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* JOCKY Source Editor */}
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '6px',
              }}
            >
              <label style={{ fontSize: '12px', fontWeight: 600, color: '#475569', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Code2 size={14} color="#2563eb" />
                <span>JOCKY FORENSIC DSL SCRIPT</span>
              </label>
              <span style={{ fontSize: '11px', color: '#64748b' }}>
                Enforced by strict IR Allow-List (Only read-only forensic operations permitted)
              </span>
            </div>

            <textarea
              rows={11}
              value={jockySource}
              onChange={(e) => {
                setJockySource(e.target.value);
                setValidationResult(null);
                setValidationError(null);
              }}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                fontFamily: 'Consolas, "Fira Code", monospace',
                fontSize: '13px',
                lineHeight: '1.5',
                boxSizing: 'border-box',
                resize: 'vertical',
              }}
              spellCheck={false}
            />
          </div>

          {/* Validation Feedback Card */}
          {validationResult && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: '6px',
                backgroundColor: validationResult.valid ? '#f0fdf4' : '#fef2f2',
                border: `1px solid ${validationResult.valid ? '#bbf7d0' : '#fecaca'}`,
                display: 'flex',
                alignItems: 'flex-start',
                gap: '10px',
              }}
            >
              {validationResult.valid ? (
                <CheckCircle2 size={18} color="#16a34a" style={{ flexShrink: 0, marginTop: '2px' }} />
              ) : (
                <AlertCircle size={18} color="#dc2626" style={{ flexShrink: 0, marginTop: '2px' }} />
              )}
              <div style={{ fontSize: '13px', color: validationResult.valid ? '#166534' : '#991b1b' }}>
                <div style={{ fontWeight: 600 }}>
                  {validationResult.valid
                    ? '✓ JOCKY Compiler & IR Allow-List Check Passed'
                    : '✗ Compilation / Safety Error'}
                </div>
                {validationResult.valid ? (
                  <div style={{ marginTop: '2px', fontSize: '12px', color: '#15803d' }}>
                    Successfully parsed {validationResult.tokens_count} tokens into{' '}
                    {validationResult.instructions_count} safe IR instructions.
                  </div>
                ) : (
                  <div style={{ marginTop: '4px', fontSize: '12px' }}>
                    {validationResult.errors.map((err, idx) => (
                      <div key={idx}>• {err}</div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {validationError && !validationResult && (
            <div
              style={{
                padding: '10px 14px',
                backgroundColor: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: '6px',
                color: '#b91c1c',
                fontSize: '13px',
              }}
            >
              {validationError}
            </div>
          )}

          {/* Form Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '8px' }}>
            <button
              type="button"
              onClick={handleValidate}
              disabled={isValidating}
              style={{
                padding: '8px 16px',
                backgroundColor: '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '6px',
                color: '#334155',
                fontSize: '13px',
                fontWeight: 600,
                cursor: isValidating ? 'not-allowed' : 'pointer',
              }}
            >
              {isValidating ? 'Validating...' : 'Validate Syntax & IR'}
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
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <Send size={14} />
              <span>{isSubmitting ? 'Dispatching...' : 'Dispatch Job'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Job Details Modal */}
      {selectedJob && (
        <Modal
          isOpen={!!selectedJob}
          onClose={() => setSelectedJob(null)}
          title={`Job Details: ${selectedJob.name}`}
          maxWidth="700px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '12px',
                backgroundColor: '#f8fafc',
                padding: '16px',
                borderRadius: '6px',
                border: '1px solid #e2e8f0',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>STATUS</div>
                <div style={{ marginTop: '4px' }}>
                  <StatusBadge status={selectedJob.status} type="job" />
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>TARGET AGENT</div>
                <div style={{ fontSize: '13px', fontFamily: 'monospace', color: '#0f172a', marginTop: '4px' }}>
                  {selectedJob.agent_id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>CREATED AT</div>
                <div style={{ fontSize: '12px', color: '#334155', marginTop: '4px' }}>
                  {new Date(selectedJob.created_at).toLocaleString()}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>COMPLETED AT</div>
                <div style={{ fontSize: '12px', color: '#334155', marginTop: '4px' }}>
                  {selectedJob.completed_at ? new Date(selectedJob.completed_at).toLocaleString() : 'Pending/Running'}
                </div>
              </div>
            </div>

            {selectedJob.error && (
              <div
                style={{
                  padding: '12px',
                  backgroundColor: '#fef2f2',
                  border: '1px solid #fecaca',
                  borderRadius: '6px',
                  color: '#b91c1c',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '12px' }}>Execution Failure:</div>
                <div style={{ fontSize: '13px', marginTop: '4px' }}>{selectedJob.error}</div>
              </div>
            )}

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#475569', marginBottom: '6px' }}>
                JOCKY SOURCE SCRIPT
              </div>
              <pre
                style={{
                  backgroundColor: '#0f172a',
                  color: '#38bdf8',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  overflowX: 'auto',
                  fontFamily: 'Consolas, "Fira Code", monospace',
                }}
              >
                {selectedJob.jocky_source}
              </pre>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
