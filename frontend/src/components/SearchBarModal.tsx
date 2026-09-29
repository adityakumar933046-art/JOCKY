import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SearchResponse, SearchResultItem } from '../types/api';
import { Search, X, ShieldAlert, Cpu, Network, FileText, Server, AlertTriangle } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export const SearchBarModal: React.FC<Props> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setSearched(true);
    try {
      const resp = await api.search(query.trim());
      setResults(resp.results || []);
    } catch (err) {
      console.error(err);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const getIcon = (type: string) => {
    switch (type) {
      case 'INDICATOR': return <AlertTriangle size={16} className="text-yellow-400" />;
      case 'FINDING': return <ShieldAlert size={16} className="text-rose-400" />;
      case 'ARTIFACT': return <Cpu size={16} className="text-blue-400" />;
      case 'EVIDENCE': return <FileText size={16} className="text-emerald-400" />;
      case 'AGENT': return <Server size={16} className="text-cyan-400" />;
      default: return <Search size={16} className="text-slate-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-slate-950/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[75vh]">
        {/* Search Input Bar */}
        <form onSubmit={handleSearch} className="flex items-center px-4 py-3.5 border-b border-slate-800 gap-3 bg-slate-950">
          <Search size={20} className="text-slate-400 shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IPs, domains, hashes, process names, paths, or findings across organization..."
            className="flex-1 bg-transparent text-slate-100 placeholder-slate-500 text-sm focus:outline-none"
            autoFocus
          />
          {query && (
            <button
              type="button"
              onClick={() => { setQuery(''); setResults([]); setSearched(false); }}
              className="text-slate-500 hover:text-slate-300"
            >
              <X size={16} />
            </button>
          )}
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-3 py-1 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded text-xs font-semibold transition"
          >
            {loading ? 'Searching...' : 'Search'}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="p-1 text-slate-500 hover:text-slate-300 ml-1"
          >
            <X size={18} />
          </button>
        </form>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading && (
            <div className="py-8 text-center text-slate-400 text-sm">
              Querying forensic entities across endpoints...
            </div>
          )}

          {!loading && searched && results.length === 0 && (
            <div className="py-8 text-center text-slate-500 text-sm">
              No artifacts, indicators, or findings matched <span className="text-slate-300 font-mono">"{query}"</span>.
            </div>
          )}

          {!searched && !loading && (
            <div className="py-8 text-center text-slate-500 text-xs">
              <p>Type an IP address, file path, SHA-256 hash, or keyword to pivot across forensic evidence.</p>
              <p className="mt-2 text-slate-600 font-mono">Example: "198.51.100.45", "cmd.exe", "temp", "CRITICAL"</p>
            </div>
          )}

          {results.map((item, idx) => (
            <div
              key={`${item.entity_type}-${item.entity_id}-${idx}`}
              className="flex items-start gap-3 p-3 bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 rounded-lg transition"
            >
              <div className="mt-0.5 p-1.5 rounded bg-slate-800/80 shrink-0">
                {getIcon(item.entity_type)}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-200 text-xs truncate">{item.title}</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400 shrink-0">
                    {item.entity_type}
                  </span>
                  {item.severity && (
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                      item.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                      item.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {item.severity}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{item.subtitle}</p>
              </div>
              {item.timestamp && (
                <span className="text-[10px] text-slate-500 font-mono shrink-0">
                  {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
