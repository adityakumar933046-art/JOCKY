import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CrossSystemCorrelation, CorrelatedFinding } from '../types/api';
import { Header } from '../components/Header';
import {
  Share2,
  RefreshCw,
  AlertTriangle,
  ShieldAlert,
  Server,
  Activity,
  Layers,
  Search,
  ExternalLink,
} from 'lucide-react';

export const CorrelationDashboardPage: React.FC = () => {
  const [xcorrs, setXcorrs] = useState<CrossSystemCorrelation[]>([]);
  const [findings, setFindings] = useState<CorrelatedFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const loadData = async () => {
    try {
      setLoading(true);
      const [xc, cf] = await Promise.all([
        api.getCrossSystemCorrelations(),
        api.getCorrelatedFindings(),
      ]);
      setXcorrs(xc);
      setFindings(cf);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunCorrelation = async () => {
    try {
      setRunning(true);
      await api.runCorrelation();
      await loadData();
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  const filteredXcorrs = xcorrs.filter(xc => {
    if (search && !xc.indicator_value.toLowerCase().includes(search.toLowerCase())) return false;
    if (severityFilter && xc.severity !== severityFilter) return false;
    if (typeFilter && xc.indicator_type !== typeFilter) return false;
    return true;
  });

  return (
    <div className="flex-1 overflow-y-auto bg-slate-950 p-6 space-y-6">
      <Header
        title="Cross-System Forensic Correlation"
        subtitle="Detect and correlate identical attack indicators, C2 channels, and threat chains spanning endpoints."
        action={
          <button
            onClick={handleRunCorrelation}
            disabled={running}
            className="flex items-center gap-2 px-3.5 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-lg shadow-sky-600/20 transition"
          >
            <RefreshCw size={14} className={running ? 'animate-spin' : ''} />
            {running ? 'Analyzing Telemetry...' : 'Run Correlation Analysis'}
          </button>
        }
      />

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-xs">Cross-System IOCs</p>
            <p className="text-2xl font-bold text-rose-400 mt-1">{xcorrs.length}</p>
          </div>
          <div className="p-2.5 bg-rose-950/50 border border-rose-800/60 rounded-lg text-rose-400">
            <AlertTriangle size={20} />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-xs">Correlated Threat Chains</p>
            <p className="text-2xl font-bold text-amber-400 mt-1">{findings.length}</p>
          </div>
          <div className="p-2.5 bg-amber-950/50 border border-amber-800/60 rounded-lg text-amber-400">
            <Layers size={20} />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-xs">Multi-Endpoint Scope</p>
            <p className="text-2xl font-bold text-cyan-400 mt-1">
              {new Set(xcorrs.flatMap(x => x.agent_ids)).size}
            </p>
          </div>
          <div className="p-2.5 bg-cyan-950/50 border border-cyan-800/60 rounded-lg text-cyan-400">
            <Server size={20} />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-xs">Correlation Engine Status</p>
            <p className="text-2xl font-bold text-emerald-400 mt-1">ACTIVE</p>
          </div>
          <div className="p-2.5 bg-emerald-950/50 border border-emerald-800/60 rounded-lg text-emerald-400">
            <Activity size={20} />
          </div>
        </div>
      </div>

      {/* Correlated Threat Chains & Campaigns */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert size={16} className="text-rose-400" />
            Correlated Multi-Stage Campaigns ({findings.length})
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {findings.map((cf) => (
              <div
                key={cf.correlation_id}
                className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 p-4 rounded-xl space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      cf.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                      cf.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {cf.severity}
                    </span>
                    <span className="ml-2 text-xs font-mono text-slate-500">{cf.category}</span>
                    <h3 className="text-sm font-semibold text-slate-100 mt-1.5">{cf.title}</h3>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-[11px] text-slate-500 font-mono">Confidence:</span>
                    <p className="text-xs font-bold text-sky-400">{Math.round(cf.confidence * 100)}%</p>
                  </div>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{cf.description}</p>

                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-500 font-medium">Affected Systems:</span>
                    {cf.agent_ids.map(agId => (
                      <span key={agId} className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[10px]">
                        {agId}
                      </span>
                    ))}
                  </div>
                  <span className="text-slate-500 font-mono text-[10px]">
                    {cf.artifact_ids.length} Artifacts Linked
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cross-System Indicator Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Share2 size={16} className="text-sky-400" />
              Cross-System Indicator Matrix
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Identical indicators observed across multiple endpoints</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter indicator..."
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-700"
              />
            </div>

            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none"
            >
              <option value="">All Types</option>
              <option value="IPV4">IPv4</option>
              <option value="SHA256">SHA256</option>
              <option value="MD5">MD5</option>
              <option value="FILE_PATH">File Path</option>
              <option value="PROCESS_NAME">Process Name</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="INFO">Info</option>
            </select>
          </div>
        </div>

        {/* Matrix Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-semibold">
              <tr>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Indicator Value</th>
                <th className="py-2.5 px-3">Endpoints Present ({xcorrs.length})</th>
                <th className="py-2.5 px-3">Hits</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">First Seen</th>
                <th className="py-2.5 px-3">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    Loading cross-system correlation matrix...
                  </td>
                </tr>
              ) : filteredXcorrs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No multi-system indicators discovered. Click "Run Correlation Analysis" above to process latest telemetry.
                  </td>
                </tr>
              ) : (
                filteredXcorrs.map((xc) => (
                  <tr key={xc.correlation_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-slate-300">
                        {xc.indicator_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono font-medium text-slate-100 max-w-xs truncate" title={xc.indicator_value}>
                      {xc.indicator_value}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {xc.agent_ids.map((ag) => (
                          <span key={ag} className="px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/70 text-cyan-300 font-mono text-[10px]">
                            {ag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{xc.occurrences}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        xc.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        xc.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                        xc.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {xc.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                      {new Date(xc.first_seen).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                      {new Date(xc.last_seen).toLocaleDateString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
