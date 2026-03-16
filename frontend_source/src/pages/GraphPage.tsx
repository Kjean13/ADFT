import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useADFT } from '@/context/ADFTContext';
import type { EntityEdge, EntityNode } from '@/engine/types';
import { Input } from '@/components/ui/input';
import { GitBranch, Move, Search, ZoomIn, ZoomOut, RotateCcw, ChevronsRight, Clock3, ShieldAlert, Network, Maximize2, Minimize2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatTimestamp } from '@/lib/forensic-utils';
import { entityTypeLabel, useLanguage } from '@/context/LanguageContext';

const typeColors: Record<string, string> = {
  user: '#3b82f6',
  host: '#10b981',
  ip: '#f59e0b',
  process: '#8b5cf6',
  service: '#ec4899',
  ad_object: '#ef4444',
};

const PAGE_SIZE = 50;

type Point = { x: number; y: number };

type DragState =
  | { kind: 'pan'; lastX: number; lastY: number }
  | { kind: 'node'; nodeId: string; lastX: number; lastY: number }
  | null;

function safeDateValue(value?: string | null): number | null {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

function isoToLocalInput(value?: string | null): string {
  const ts = safeDateValue(value);
  if (!ts) return '';
  const d = new Date(ts);
  const pad = (n: number) => `${n}`.padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localInputToEpoch(value: string): number | null {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

function overlapsRange(edge: EntityEdge, start: number | null, end: number | null): boolean {
  if (start === null && end === null) return true;
  const first = safeDateValue(edge.firstSeen) ?? safeDateValue(edge.lastSeen);
  const last = safeDateValue(edge.lastSeen) ?? safeDateValue(edge.firstSeen);
  if (first === null && last === null) return true;
  const min = Math.min(first ?? last ?? 0, last ?? first ?? 0);
  const max = Math.max(first ?? last ?? 0, last ?? first ?? 0);
  if (start !== null && max < start) return false;
  if (end !== null && min > end) return false;
  return true;
}

export default function GraphPage() {
  const { run } = useADFT();
  const { t, language } = useLanguage();
  const { entityGraph, reconstruction } = run;
  const containerRef = useRef<HTMLDivElement>(null);
  const graphShellRef = useRef<HTMLDivElement>(null);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [centerNodeId, setCenterNodeId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const [manualPositions, setManualPositions] = useState<Record<string, Point>>({});
  const [view, setView] = useState({ scale: 1, x: 0, y: 0 });
  const [drag, setDrag] = useState<DragState>(null);
  const [timeStart, setTimeStart] = useState<string>(isoToLocalInput(entityGraph.timeframe?.start));
  const [timeEnd, setTimeEnd] = useState<string>(isoToLocalInput(entityGraph.timeframe?.end));
  const [isFullscreen, setIsFullscreen] = useState(false);

  const nodeMap = useMemo(() => new Map(entityGraph.nodes.map((node) => [node.id, node])), [entityGraph.nodes]);
  const startEpoch = useMemo(() => localInputToEpoch(timeStart), [timeStart]);
  const endEpoch = useMemo(() => localInputToEpoch(timeEnd), [timeEnd]);

  const edgesInWindow = useMemo(() => entityGraph.edges.filter((edge) => overlapsRange(edge, startEpoch, endEpoch)), [entityGraph.edges, startEpoch, endEpoch]);

  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>();
    edgesInWindow.forEach((edge) => {
      if (!map.has(edge.source)) map.set(edge.source, new Set());
      if (!map.has(edge.target)) map.set(edge.target, new Set());
      map.get(edge.source)?.add(edge.target);
      map.get(edge.target)?.add(edge.source);
    });
    return map;
  }, [edgesInWindow]);

  const defaultCenterId = useMemo(() => {
    const preferred = entityGraph.nodes.find((node) => node.label.toLowerCase() === (reconstruction.patientZero.entity || '').toLowerCase());
    return preferred?.id || entityGraph.nodes[0]?.id || null;
  }, [entityGraph.nodes, reconstruction.patientZero.entity]);

  useEffect(() => {
    if (!centerNodeId && defaultCenterId) {
      setCenterNodeId(defaultCenterId);
      setSelectedNodeId(defaultCenterId);
    }
  }, [centerNodeId, defaultCenterId]);

  useEffect(() => {
    setTimeStart(isoToLocalInput(entityGraph.timeframe?.start));
    setTimeEnd(isoToLocalInput(entityGraph.timeframe?.end));
  }, [entityGraph.timeframe?.start, entityGraph.timeframe?.end]);

  useEffect(() => {
    const onFullscreenChange = () => {
      const active = document.fullscreenElement === graphShellRef.current;
      setIsFullscreen(active);
      requestAnimationFrame(() => {
        const box = containerRef.current?.getBoundingClientRect();
        if (box) {
          setView((current) => ({ ...current, x: box.width / 2, y: box.height / 2 }));
        }
      });
    };

    document.addEventListener('fullscreenchange', onFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', onFullscreenChange);
  }, []);

  useEffect(() => {
    setPage(0);
    setManualPositions({});
  }, [centerNodeId, expandedNodes, typeFilter, search, timeStart, timeEnd]);

  useEffect(() => {
    const box = containerRef.current?.getBoundingClientRect();
    if (box) {
      setView({ scale: 1, x: box.width / 2, y: box.height / 2 });
    }
  }, [centerNodeId]);

  const centerId = centerNodeId || defaultCenterId;
  const centerNode = centerId ? nodeMap.get(centerId) || null : null;

  const visibleIds = useMemo(() => {
    if (!centerId) return [] as string[];
    const visited = new Set<string>([centerId]);
    const queue: Array<{ id: string; depth: number }> = [{ id: centerId, depth: 0 }];

    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;
      const neighbors = [...(adjacency.get(current.id) || new Set<string>())];
      const shouldExpand = current.depth === 0 || expandedNodes.includes(current.id);
      if (!shouldExpand) continue;
      neighbors.forEach((neighborId) => {
        if (!visited.has(neighborId)) {
          visited.add(neighborId);
          queue.push({ id: neighborId, depth: current.depth + 1 });
        }
      });
    }

    return [...visited];
  }, [adjacency, centerId, expandedNodes]);

  const filteredNodes = useMemo(() => {
    const searchLower = search.toLowerCase();
    return visibleIds
      .map((id) => nodeMap.get(id))
      .filter((node): node is EntityNode => Boolean(node))
      .filter((node) => {
        if (typeFilter && node.type !== typeFilter) return false;
        if (searchLower && !node.label.toLowerCase().includes(searchLower)) return false;
        return true;
      })
      .sort((a, b) => b.risk - a.risk || b.alertCount - a.alertCount || a.label.localeCompare(b.label));
  }, [nodeMap, visibleIds, typeFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filteredNodes.length / PAGE_SIZE));
  const pagedNodes = useMemo(() => filteredNodes.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE), [filteredNodes, page]);

  useEffect(() => {
    if (page > totalPages - 1) setPage(0);
  }, [page, totalPages]);

  const pageNodeIds = useMemo(() => new Set(pagedNodes.map((node) => node.id)), [pagedNodes]);
  const pagedEdges = useMemo(() => edgesInWindow.filter((edge) => pageNodeIds.has(edge.source) && pageNodeIds.has(edge.target)), [edgesInWindow, pageNodeIds]);

  const layoutPositions = useMemo(() => {
    const positions = new Map<string, Point>();
    if (!centerId) return positions;

    positions.set(centerId, { x: 0, y: 0 });
    const firstRing = [...(adjacency.get(centerId) || new Set<string>())].filter((id) => pageNodeIds.has(id));
    const ring1Radius = 240;
    const ring2Radius = 430;

    firstRing.forEach((id, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(firstRing.length, 1);
      positions.set(id, { x: Math.cos(angle) * ring1Radius, y: Math.sin(angle) * ring1Radius });
    });

    const secondRing = pagedNodes.map((node) => node.id).filter((id) => id !== centerId && !firstRing.includes(id));
    secondRing.forEach((id, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(secondRing.length, 1);
      positions.set(id, { x: Math.cos(angle) * ring2Radius, y: Math.sin(angle) * ring2Radius });
    });

    Object.entries(manualPositions).forEach(([id, point]) => {
      if (pageNodeIds.has(id)) positions.set(id, point);
    });

    return positions;
  }, [adjacency, centerId, manualPositions, pageNodeIds, pagedNodes]);

  const selectedNode = selectedNodeId ? nodeMap.get(selectedNodeId) || null : null;
  const relatedEdges = useMemo(() => {
    if (!selectedNode) return [] as EntityEdge[];
    return edgesInWindow.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id).sort((a, b) => b.weight - a.weight || a.label.localeCompare(b.label));
  }, [edgesInWindow, selectedNode]);

  const types = [...new Set(entityGraph.nodes.map((n) => n.type))];

  const handleZoom = useCallback((factor: number) => {
    setView((current) => ({ ...current, scale: Math.min(2.5, Math.max(0.35, current.scale * factor)) }));
  }, []);

  const handleToggleFullscreen = useCallback(async () => {
    const shell = graphShellRef.current;
    if (!shell) return;

    try {
      if (document.fullscreenElement === shell) {
        await document.exitFullscreen();
      } else {
        await shell.requestFullscreen();
      }
    } catch (error) {
      console.error('Fullscreen toggle failed', error);
    }
  }, []);

  const handleWheel = useCallback((event: React.WheelEvent<SVGSVGElement>) => {
    event.preventDefault();
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const cursorX = event.clientX - rect.left;
    const cursorY = event.clientY - rect.top;
    const factor = event.deltaY < 0 ? 1.12 : 0.9;

    setView((current) => {
      const nextScale = Math.min(2.5, Math.max(0.35, current.scale * factor));
      const worldX = (cursorX - current.x) / current.scale;
      const worldY = (cursorY - current.y) / current.scale;
      return {
        scale: nextScale,
        x: cursorX - worldX * nextScale,
        y: cursorY - worldY * nextScale,
      };
    });
  }, []);

  const handleBackgroundMouseDown = useCallback((event: React.MouseEvent<SVGSVGElement>) => {
    if ((event.target as SVGElement).closest('[data-node="true"]')) return;
    setDrag({ kind: 'pan', lastX: event.clientX, lastY: event.clientY });
  }, []);

  const handleMouseMove = useCallback((event: React.MouseEvent<SVGSVGElement>) => {
    if (!drag) return;
    const dx = event.clientX - drag.lastX;
    const dy = event.clientY - drag.lastY;
    if (drag.kind === 'pan') {
      setView((current) => ({ ...current, x: current.x + dx, y: current.y + dy }));
      setDrag({ kind: 'pan', lastX: event.clientX, lastY: event.clientY });
      return;
    }

    const nodePosition = layoutPositions.get(drag.nodeId);
    if (!nodePosition) return;
    setManualPositions((current) => ({
      ...current,
      [drag.nodeId]: { x: nodePosition.x + dx / view.scale, y: nodePosition.y + dy / view.scale },
    }));
    setDrag({ kind: 'node', nodeId: drag.nodeId, lastX: event.clientX, lastY: event.clientY });
  }, [drag, layoutPositions, view.scale]);

  const handleMouseUp = useCallback(() => {
    setDrag(null);
  }, []);

  const hiddenNodeCount = Math.max(0, visibleIds.length - filteredNodes.length) + Math.max(0, filteredNodes.length - pagedNodes.length - page * PAGE_SIZE);

  if (entityGraph.nodes.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">{t('graph.title')}</h1>
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <GitBranch className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('graph.empty')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div>
        <h1 className="text-2xl font-bold">{t('graph.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('graph.subtitle')}</p>
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        <div className="relative max-w-xs w-full">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t('graph.search')} value={search} onChange={(e) => setSearch(e.target.value)} className="pl-8 h-9 text-sm bg-muted" />
        </div>
        {types.map((type) => (
          <button
            key={type}
            onClick={() => setTypeFilter(typeFilter === type ? '' : type)}
            className={cn('px-2.5 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 border', typeFilter === type ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted text-muted-foreground hover:text-foreground border-border')}
          >
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: typeColors[type] }} />
            {entityTypeLabel(language, type)}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4 min-h-0 flex-1">
        <div ref={graphShellRef} className={cn('rounded-lg border bg-card p-4 space-y-4 min-h-[720px]', isFullscreen && 'bg-background text-foreground w-full h-full overflow-auto')}>
          <div className="flex flex-wrap gap-3 items-end justify-between">
            <div className="flex flex-wrap gap-3 items-end">
              <div className="space-y-1">
                <label className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1"><Clock3 className="h-3 w-3" /> {t('graph.start')}</label>
                <Input type="datetime-local" value={timeStart} onChange={(e) => setTimeStart(e.target.value)} className="h-9 bg-muted" />
              </div>
              <div className="space-y-1">
                <label className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.end')}</label>
                <Input type="datetime-local" value={timeEnd} onChange={(e) => setTimeEnd(e.target.value)} className="h-9 bg-muted" />
              </div>
              <button onClick={() => { setTimeStart(isoToLocalInput(entityGraph.timeframe?.start)); setTimeEnd(isoToLocalInput(entityGraph.timeframe?.end)); }} className="h-9 px-3 rounded border bg-muted text-xs font-mono">
                {t('graph.fullWindow')}
              </button>
            </div>

            <div className="flex gap-2 items-center">
              <button onClick={() => handleZoom(1.12)} className="h-9 w-9 rounded border bg-muted flex items-center justify-center" title={t('graph.zoomIn')}><ZoomIn className="h-4 w-4" /></button>
              <button onClick={() => handleZoom(0.9)} className="h-9 w-9 rounded border bg-muted flex items-center justify-center" title={t('graph.zoomOut')}><ZoomOut className="h-4 w-4" /></button>
              <button onClick={() => setView((current) => ({ ...current, scale: 1 }))} className="h-9 w-9 rounded border bg-muted flex items-center justify-center" title={t('graph.resetZoom')}><RotateCcw className="h-4 w-4" /></button>
              <button onClick={handleToggleFullscreen} className="h-9 px-3 rounded border bg-muted inline-flex items-center justify-center gap-2 text-xs font-medium" title={isFullscreen ? t('graph.exitFullscreen') : t('graph.fullscreen')}>
                {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
                <span className="hidden sm:inline">{isFullscreen ? t('graph.exitFullscreen') : t('graph.fullscreen')}</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
            <div className="rounded-lg bg-muted/40 p-3">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.pivot')}</div>
              <div className="font-mono text-sm font-semibold truncate">{centerNode?.label || t('common.na')}</div>
            </div>
            <div className="rounded-lg bg-muted/40 p-3">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.nodesShown')}</div>
              <div className="font-mono text-sm font-semibold">{pagedNodes.length} / {filteredNodes.length}</div>
            </div>
            <div className="rounded-lg bg-muted/40 p-3">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.visibleLinks')}</div>
              <div className="font-mono text-sm font-semibold">{pagedEdges.length}</div>
            </div>
            <div className="rounded-lg bg-muted/40 p-3">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.zoom')}</div>
              <div className="font-mono text-sm font-semibold">{Math.round(view.scale * 100)}%</div>
            </div>
          </div>

          <div ref={containerRef} className={cn('relative rounded-lg border bg-surface-0 overflow-hidden', isFullscreen ? 'h-[calc(100vh-280px)] min-h-[680px]' : 'h-[560px]')}>
            <svg className="w-full h-full cursor-grab active:cursor-grabbing" onWheel={handleWheel} onMouseDown={handleBackgroundMouseDown} onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
              <defs>
                <marker id="graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280" />
                </marker>
              </defs>
              <rect x="0" y="0" width="100%" height="100%" fill="transparent" />
              <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
                {pagedEdges.map((edge) => {
                  const source = layoutPositions.get(edge.source);
                  const target = layoutPositions.get(edge.target);
                  if (!source || !target) return null;
                  const midX = (source.x + target.x) / 2;
                  const midY = (source.y + target.y) / 2;
                  return (
                    <g key={`${edge.source}-${edge.target}-${edge.label}`}>
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="rgba(148,163,184,0.45)" strokeWidth={Math.max(1.5, Math.min(5, edge.weight))} markerEnd="url(#graph-arrow)" />
                      <rect x={midX - 42} y={midY - 9} width="84" height="18" rx="6" fill="rgba(2, 6, 23, 0.75)" />
                      <text x={midX} y={midY + 4} textAnchor="middle" fontSize="10" fill="#cbd5e1" className="font-mono">
                        {edge.label.length > 18 ? `${edge.label.slice(0, 18)}…` : edge.label}
                      </text>
                    </g>
                  );
                })}

                {pagedNodes.map((node) => {
                  const point = layoutPositions.get(node.id) || { x: 0, y: 0 };
                  const radius = Math.max(18, Math.min(36, 16 + node.alertCount * 2 + Math.round(node.risk / 15)));
                  const color = typeColors[node.type] || '#64748b';
                  const selected = selectedNodeId === node.id;
                  const centered = centerId === node.id;
                  return (
                    <g
                      key={node.id}
                      data-node="true"
                      transform={`translate(${point.x} ${point.y})`}
                      onMouseDown={(event) => {
                        event.stopPropagation();
                        setDrag({ kind: 'node', nodeId: node.id, lastX: event.clientX, lastY: event.clientY });
                      }}
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedNodeId(node.id);
                      }}
                      className="cursor-pointer"
                    >
                      {node.isKnownIoc && <circle r={radius + 10} fill="rgba(239, 68, 68, 0.08)" stroke="rgba(239, 68, 68, 0.55)" strokeWidth="2" strokeDasharray="4 4" />}
                      {node.isCritical && !node.isKnownIoc && <circle r={radius + 8} fill="rgba(248, 113, 113, 0.10)" stroke="rgba(248, 113, 113, 0.35)" strokeWidth="2" />}
                      <circle r={radius} fill={color} stroke={selected ? '#f8fafc' : centered ? '#fde68a' : 'rgba(15,23,42,0.8)'} strokeWidth={selected ? 4 : centered ? 3 : 2} opacity={selected ? 1 : 0.96} />
                      <text y="4" textAnchor="middle" fontSize="11" fill="#020617" className="font-bold">{Math.round(node.risk)}</text>
                      <text y={radius + 16} textAnchor="middle" fontSize="11" fill="#e5e7eb" className="font-mono">
                        {node.label.length > 18 ? `${node.label.slice(0, 18)}…` : node.label}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>

            <div className="absolute left-3 top-3 flex items-center gap-2 text-[11px] text-muted-foreground bg-background/80 rounded-lg px-3 py-2 border">
              <Move className="h-3.5 w-3.5" />
              <span>{t('graph.help')}</span>
            </div>

            <div className="absolute left-3 bottom-3 flex flex-wrap gap-3 text-[10px] bg-background/80 rounded-lg px-3 py-2 border">
              {Object.keys(typeColors).map((type) => (
                <div key={type} className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: typeColors[type] }} />
                  <span className="text-muted-foreground">{entityTypeLabel(language, type)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-3 text-xs text-muted-foreground">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="inline-flex items-center gap-1"><ShieldAlert className="h-3.5 w-3.5" /> {t('graph.iocKnown')}</span>
              <span className="inline-flex items-center gap-1"><Network className="h-3.5 w-3.5" /> {t('graph.maxNodes')}</span>
              {hiddenNodeCount > 0 && <span>{t('graph.hidden', { count: hiddenNodeCount })}</span>}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0} className="px-2 py-1 rounded border disabled:opacity-40">{t('graph.prev')}</button>
              <span className="font-mono">{t('graph.page', { page: page + 1, total: totalPages })}</span>
              <button onClick={() => setPage((current) => Math.min(totalPages - 1, current + 1))} disabled={page >= totalPages - 1} className="px-2 py-1 rounded border disabled:opacity-40">{t('graph.next')}</button>
            </div>
          </div>
        </div>

        <div className="rounded-lg border bg-card p-4 space-y-4 overflow-auto">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('graph.selectedNode')}</h2>
          </div>

          {!selectedNode ? (
            <p className="text-sm text-muted-foreground">{t('graph.selectPrompt')}</p>
          ) : (
            <>
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-lg font-bold font-mono break-all">{selectedNode.label}</div>
                    <div className="text-xs text-muted-foreground">{entityTypeLabel(language, selectedNode.type)} • {t('common.role')} {selectedNode.role || 'entity'}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.risk')}</div>
                    <div className="text-2xl font-bold font-mono">{selectedNode.risk}</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.alerts')}</div><div className="font-mono text-sm font-semibold">{selectedNode.alertCount}</div></div>
                  <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.degree')}</div><div className="font-mono text-sm font-semibold">{selectedNode.degree || 0}</div></div>
                  <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.firstSeen')}</div><div className="font-mono text-[11px]">{selectedNode.firstSeen ? formatTimestamp(selectedNode.firstSeen) : t('common.na')}</div></div>
                  <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{t('graph.lastSeen')}</div><div className="font-mono text-[11px]">{selectedNode.lastSeen ? formatTimestamp(selectedNode.lastSeen) : t('common.na')}</div></div>
                </div>

                <div className="flex flex-wrap gap-2 text-[11px]">
                  <span className={cn('px-2 py-1 rounded border', selectedNode.isCritical ? 'border-red-400/40 bg-red-500/10 text-red-200' : 'border-border bg-muted text-muted-foreground')}>
                    {selectedNode.isCritical ? t('graph.criticalEntity') : t('graph.standardCriticality')}
                  </span>
                  <span className={cn('px-2 py-1 rounded border', selectedNode.isKnownIoc ? 'border-red-400/40 bg-red-500/10 text-red-200' : 'border-border bg-muted text-muted-foreground')}>
                    {selectedNode.isKnownIoc ? t('graph.iocKnown').replace(' = red dashed ring', '').replace(' = anneau pointillé rouge', '') : t('graph.noKnownIoc')}
                  </span>
                  <span className="px-2 py-1 rounded border bg-muted text-muted-foreground">{t('graph.graphOccurrences', { count: selectedNode.clusterSize || 0 })}</span>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button onClick={() => { setCenterNodeId(selectedNode.id); setSelectedNodeId(selectedNode.id); }} className="px-3 py-2 rounded border bg-primary text-primary-foreground text-xs font-medium">
                  {t('graph.centerNode')}
                </button>
                <button onClick={() => { setExpandedNodes((current) => current.includes(selectedNode.id) ? current.filter((id) => id !== selectedNode.id) : [...current, selectedNode.id]); }} className="px-3 py-2 rounded border bg-muted text-xs font-medium inline-flex items-center gap-1">
                  <ChevronsRight className="h-3.5 w-3.5" />
                  {expandedNodes.includes(selectedNode.id) ? t('graph.collapse') : t('graph.expand')}
                </button>
              </div>

              <div className="space-y-2">
                <div className="text-sm font-semibold">{t('graph.visibleRelations')}</div>
                <div className="space-y-2 max-h-[360px] overflow-auto pr-1">
                  {relatedEdges.length === 0 ? (
                    <p className="text-xs text-muted-foreground">{t('graph.noRelations')}</p>
                  ) : relatedEdges.map((edge, index) => {
                    const neighborId = edge.source === selectedNode.id ? edge.target : edge.source;
                    const neighbor = nodeMap.get(neighborId);
                    return (
                      <button key={`${edge.source}-${edge.target}-${index}`} onClick={() => setSelectedNodeId(neighborId)} className="w-full text-left rounded-lg border bg-muted/30 p-3 hover:bg-muted/50">
                        <div className="text-xs text-muted-foreground font-mono">{edge.label}</div>
                        <div className="text-sm font-semibold break-all">{neighbor?.label || neighborId}</div>
                        <div className="text-[11px] text-muted-foreground mt-1">
                          {t('graph.weight')} {edge.weight}
                          {edge.firstSeen && ` • ${formatTimestamp(edge.firstSeen)}`}
                          {edge.lastSeen && edge.lastSeen !== edge.firstSeen && ` → ${formatTimestamp(edge.lastSeen)}`}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
