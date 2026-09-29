import React, { useState, useMemo } from 'react';
import { InvestigationGraph, GraphNode, GraphEdge } from '../types/api';
import { ZoomIn, ZoomOut, RotateCcw, Filter, Eye, Shield, Activity, Network, FileCode, Cpu, AlertTriangle } from 'lucide-react';

interface Props {
  graph: InvestigationGraph;
}

const TYPE_COLORS: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  SYSTEM: { bg: 'fill-cyan-950/70', border: 'stroke-cyan-500', text: 'text-cyan-400', dot: 'bg-cyan-500' },
  PROCESS: { bg: 'fill-blue-950/70', border: 'stroke-blue-500', text: 'text-blue-400', dot: 'bg-blue-500' },
  NETWORK: { bg: 'fill-purple-950/70', border: 'stroke-purple-500', text: 'text-purple-400', dot: 'bg-purple-500' },
  FILE: { bg: 'fill-emerald-950/70', border: 'stroke-emerald-500', text: 'text-emerald-400', dot: 'bg-emerald-500' },
  SERVICE: { bg: 'fill-amber-950/70', border: 'stroke-amber-500', text: 'text-amber-400', dot: 'bg-amber-500' },
  DRIVER: { bg: 'fill-orange-950/70', border: 'stroke-orange-500', text: 'text-orange-400', dot: 'bg-orange-500' },
  PERSISTENCE: { bg: 'fill-red-950/70', border: 'stroke-red-500', text: 'text-red-400', dot: 'bg-red-500' },
  FINDING: { bg: 'fill-rose-950/80', border: 'stroke-rose-500', text: 'text-rose-400', dot: 'bg-rose-500' },
  INDICATOR: { bg: 'fill-yellow-950/80', border: 'stroke-yellow-500', text: 'text-yellow-400', dot: 'bg-yellow-500' },
};

export const InvestigationGraphView: React.FC<Props> = ({ graph }) => {
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hiddenTypes, setHiddenTypes] = useState<Record<string, boolean>>({});

  const toggleType = (t: string) => {
    setHiddenTypes(prev => ({ ...prev, [t]: !prev[t] }));
  };

  // Filter nodes & edges
  const filteredNodes = useMemo(() => {
    return graph.nodes.filter(n => !hiddenTypes[n.type]);
  }, [graph.nodes, hiddenTypes]);

  const activeNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return graph.edges.filter(e => activeNodeIds.has(e.source) && activeNodeIds.has(e.target));
  }, [graph.edges, activeNodeIds]);

  // Deterministic circular / clustered layout calculation
  const layout = useMemo(() => {
    const width = 900;
    const height = 550;
    const centerX = width / 2;
    const centerY = height / 2;

    const coords: Record<string, { x: number; y: number }> = {};
    const n = filteredNodes.length;
    if (n === 0) return { coords, width, height };

    // Group nodes by type
    const byType: Record<string, GraphNode[]> = {};
    filteredNodes.forEach(node => {
      byType[node.type] = byType[node.type] || [];
      byType[node.type].push(node);
    });

    // Place SYSTEM nodes in inner center
    const systems = byType['SYSTEM'] || [];
    systems.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / (systems.length || 1);
      coords[node.id] = {
        x: centerX + Math.cos(angle) * (systems.length > 1 ? 90 : 0),
        y: centerY + Math.sin(angle) * (systems.length > 1 ? 90 : 0),
      };
    });

    // Place PROCESS nodes in ring 1
    const procs = byType['PROCESS'] || [];
    procs.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / (procs.length || 1);
      coords[node.id] = {
        x: centerX + Math.cos(angle) * 180,
        y: centerY + Math.sin(angle) * 160,
      };
    });

    // Place other artifacts (NETWORK, FILE, SERVICE, etc.) in ring 2
    const otherTypes = ['NETWORK', 'FILE', 'SERVICE', 'DRIVER', 'PERSISTENCE'];
    const artifacts = filteredNodes.filter(n => otherTypes.includes(n.type));
    artifacts.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / (artifacts.length || 1) + 0.3;
      coords[node.id] = {
        x: centerX + Math.cos(angle) * 280,
        y: centerY + Math.sin(angle) * 230,
      };
    });

    // Place FINDING & INDICATOR in outer ring
    const alerts = filteredNodes.filter(n => ['FINDING', 'INDICATOR'].includes(n.type));
    alerts.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / (alerts.length || 1) + 0.7;
      coords[node.id] = {
        x: centerX + Math.cos(angle) * 380,
        y: centerY + Math.sin(angle) * 290,
      };
    });

    // Fallback for any unpositioned
    filteredNodes.forEach(node => {
      if (!coords[node.id]) {
        coords[node.id] = { x: centerX + (Math.random() - 0.5) * 400, y: centerY + (Math.random() - 0.5) * 300 };
      }
    });

    return { coords, width, height };
  }, [filteredNodes]);

  return (
    <div className="flex flex-col h-full bg-slate-950 border border-slate-800 rounded-xl overflow-hidden relative">
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 text-xs text-slate-300 gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-200">Nodes: {filteredNodes.length}</span>
          <span className="text-slate-600">|</span>
          <span className="font-semibold text-slate-200">Edges: {filteredEdges.length}</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">Severity: <span className="font-bold text-rose-400">{graph.metrics?.highest_severity || 'INFO'}</span></span>
        </div>

        {/* Node Type Filter Toggles */}
        <div className="flex flex-wrap items-center gap-1.5">
          {Object.keys(TYPE_COLORS).map(type => {
            const count = graph.metrics?.entities_by_type?.[type] || 0;
            if (count === 0) return null;
            const isHidden = hiddenTypes[type];
            return (
              <button
                key={type}
                onClick={() => toggleType(type)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition flex items-center gap-1 border ${
                  isHidden
                    ? 'bg-slate-900 border-slate-800 text-slate-600 line-through'
                    : 'bg-slate-800/80 border-slate-700 text-slate-200 hover:border-slate-500'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${TYPE_COLORS[type].dot}`} />
                {type} ({count})
              </button>
            );
          })}
        </div>

        {/* Zoom Controls */}
        <div className="flex items-center gap-1 bg-slate-800/60 rounded p-1 border border-slate-700">
          <button
            onClick={() => setZoom(z => Math.max(0.4, z - 0.15))}
            className="p-1 hover:bg-slate-700 rounded text-slate-300"
            title="Zoom Out"
          >
            <ZoomOut size={14} />
          </button>
          <span className="px-1 text-[11px] text-slate-400 font-mono">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom(z => Math.min(2.5, z + 0.15))}
            className="p-1 hover:bg-slate-700 rounded text-slate-300"
            title="Zoom In"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={() => setZoom(1)}
            className="p-1 hover:bg-slate-700 rounded text-slate-300"
            title="Reset Zoom"
          >
            <RotateCcw size={14} />
          </button>
        </div>
      </div>

      {/* Main Canvas + Detail Drawer */}
      <div className="flex-1 relative overflow-auto bg-grid-slate-900/40">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="w-full h-full min-h-[500px] cursor-grab active:cursor-grabbing"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center center', transition: 'transform 0.1s ease' }}
        >
          {/* Arrowhead marker */}
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
            </marker>
          </defs>

          {/* Render Edges */}
          {filteredEdges.map(edge => {
            const src = layout.coords[edge.source];
            const dst = layout.coords[edge.target];
            if (!src || !dst) return null;

            const isSelected = selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

            return (
              <g key={edge.id}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  stroke={isSelected ? '#38bdf8' : '#334155'}
                  strokeWidth={isSelected ? 2 : 1.2}
                  strokeDasharray={edge.relationship === 'EXTRACTED_FROM' ? '3,3' : undefined}
                  markerEnd="url(#arrow)"
                />
                <text
                  x={(src.x + dst.x) / 2}
                  y={(src.y + dst.y) / 2 - 4}
                  fill="#94a3b8"
                  fontSize="9"
                  textAnchor="middle"
                  className="select-none font-mono pointer-events-none"
                >
                  {edge.relationship}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {filteredNodes.map(node => {
            const pos = layout.coords[node.id];
            if (!pos) return null;
            const style = TYPE_COLORS[node.type] || TYPE_COLORS.SYSTEM;
            const isSelected = selectedNode?.id === node.id;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                {/* Node Shape */}
                <circle
                  r={node.type === 'SYSTEM' ? 24 : node.type === 'FINDING' ? 20 : 16}
                  className={`${style.bg} ${style.border} stroke-2 transition-all ${
                    isSelected ? 'ring-4 ring-sky-400 stroke-sky-300 r-[26px]' : 'group-hover:stroke-white'
                  }`}
                />

                {/* Node Label */}
                <text
                  y={node.type === 'SYSTEM' ? 36 : 28}
                  fill="#e2e8f0"
                  fontSize="10"
                  fontWeight={isSelected ? 'bold' : 'normal'}
                  textAnchor="middle"
                  className="select-none font-sans pointer-events-none drop-shadow-md"
                >
                  {node.label.length > 22 ? node.label.substring(0, 20) + '...' : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 max-h-[85%] bg-slate-900/95 border border-slate-700/80 rounded-lg shadow-2xl p-4 overflow-y-auto text-xs backdrop-blur-md z-20">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-3">
              <div className="flex items-center gap-1.5">
                <span className={`w-2.5 h-2.5 rounded-full ${TYPE_COLORS[selectedNode.type]?.dot || 'bg-slate-400'}`} />
                <span className="font-bold text-slate-100">{selectedNode.type}</span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-200 font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2">
              <div>
                <span className="text-slate-400">Label:</span>
                <p className="font-mono text-slate-200 font-medium break-all">{selectedNode.label}</p>
              </div>
              <div>
                <span className="text-slate-400">Node ID:</span>
                <p className="font-mono text-slate-400 text-[11px] break-all">{selectedNode.id}</p>
              </div>
              {selectedNode.agent_id && (
                <div>
                  <span className="text-slate-400">Endpoint / Agent:</span>
                  <p className="font-mono text-cyan-400 font-medium">{selectedNode.agent_id}</p>
                </div>
              )}
              <div>
                <span className="text-slate-400">Severity:</span>
                <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-bold ${
                  selectedNode.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                  selectedNode.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                  selectedNode.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                  'bg-slate-800 text-slate-300'
                }`}>
                  {selectedNode.severity}
                </span>
              </div>

              {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                <div className="pt-2 border-t border-slate-800">
                  <span className="text-slate-400 block mb-1 font-semibold">Normalized Attributes:</span>
                  <pre className="bg-slate-950 p-2 rounded text-[10px] font-mono text-slate-300 overflow-x-auto border border-slate-800 max-h-48">
                    {JSON.stringify(selectedNode.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
