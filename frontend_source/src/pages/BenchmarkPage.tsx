import { useMemo, type ReactNode } from 'react';
import { useADFT } from '@/context/ADFTContext';
import { Gauge, ShieldCheck, DatabaseZap, Files, Workflow, Activity, HardDrive, Network } from 'lucide-react';
import { formatTimestamp } from '@/lib/forensic-utils';
import { useLanguage } from '@/context/LanguageContext';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

function density(alerts: number, events: number): string {
  if (!events) return '0.00%';
  return `${((alerts / events) * 100).toFixed(2)}%`;
}

function formatRatePerMinute(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return 'N/A';
  return `${value.toFixed(value >= 1000 ? 0 : value >= 100 ? 1 : 2)} evt/min`;
}

function formatSeconds(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return 'N/A';
  return `${value.toFixed(value >= 10 ? 1 : 2)} s`;
}


function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function safeDate(ts?: string | null): Date | null {
  if (!ts) return null;
  const parsed = new Date(ts);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function shortTime(ts: number): string {
  return new Date(ts).toLocaleString([], {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function bucketSizeSeconds(spanSeconds: number): number {
  if (spanSeconds <= 3600) return 60;
  if (spanSeconds <= 6 * 3600) return 300;
  if (spanSeconds <= 24 * 3600) return 900;
  if (spanSeconds <= 7 * 24 * 3600) return 3600;
  return 4 * 3600;
}

export default function BenchmarkPage() {
  const { run, health, capabilities, artifacts, conversionManifest, lastRefreshAt } = useADFT();
  const { t } = useLanguage();
  const benchmark = run.benchmark;

  const manifestSummary = useMemo(() => {
    const summary = (conversionManifest as { summary?: Record<string, number> } | null)?.summary;
    return summary || null;
  }, [conversionManifest]);

  const checks = [
    { label: 'CLI', ok: true, detail: health?.release ? 'adft entrypoint ready' : 'backend not yet initialized' },
    { label: 'GUI', ok: true, detail: 'packaged assets served by backend' },
    { label: 'EVTX', ok: capabilities?.evtx_available ?? false, detail: capabilities?.evtx_available ? t('analysis.evtxAvailable') : t('analysis.evtxMissing') },
    { label: 'Formats', ok: (capabilities?.supported_inputs.length || 0) >= 10, detail: `${capabilities?.supported_inputs.length || 0}` },
    { label: 'Artifacts', ok: artifacts.length > 0, detail: `${artifacts.length}` },
  ];

  const artifactFootprint = useMemo(
    () => artifacts.reduce((total, artifact) => total + (artifact.size_bytes || 0), 0),
    [artifacts],
  );

  const timeStats = useMemo(() => {
    const dates = run.normalizedEvents
      .map((event) => safeDate(event.timestamp))
      .filter((date): date is Date => Boolean(date))
      .sort((a, b) => a.getTime() - b.getTime());

    if (dates.length === 0) {
      return {
        start: null as Date | null,
        end: null as Date | null,
        spanSeconds: 0,
        bucketSeconds: 60,
        averageRate: 0,
      };
    }

    const start = dates[0];
    const end = dates[dates.length - 1];
    const rawSpan = Math.max(1, Math.round((end.getTime() - start.getTime()) / 1000));
    const bucketSeconds = bucketSizeSeconds(rawSpan);

    return {
      start,
      end,
      spanSeconds: rawSpan,
      bucketSeconds,
      averageRate: run.normalizedEvents.length / rawSpan,
    };
  }, [run.normalizedEvents]);

  const activitySeries = useMemo(() => {
    if (!timeStats.start || !timeStats.end) return [] as Array<{ bucket: string; events: number }>;

    const startMs = timeStats.start.getTime();
    const bucketMs = timeStats.bucketSeconds * 1000;
    const counters = new Map<number, number>();

    run.normalizedEvents.forEach((event) => {
      const date = safeDate(event.timestamp);
      if (!date) return;
      const slot = Math.floor((date.getTime() - startMs) / bucketMs);
      counters.set(slot, (counters.get(slot) || 0) + 1);
    });

    const bucketCount = Math.max(1, Math.min(72, Math.floor(timeStats.spanSeconds / timeStats.bucketSeconds) + 1));
    return Array.from({ length: bucketCount }, (_, index) => ({
      bucket: shortTime(startMs + index * bucketMs),
      events: counters.get(index) || 0,
    }));
  }, [run.normalizedEvents, timeStats]);

  const peakBucket = useMemo(() => activitySeries.reduce((max, point) => Math.max(max, point.events), 0), [activitySeries]);

  const pipelineSeries = useMemo(() => {
    const values = [
      { name: t('benchmark.series.events'), value: benchmark?.pipeline.rawEvents ?? run.normalizedEvents.length },
      { name: t('benchmark.series.alerts'), value: benchmark?.pipeline.alerts ?? run.alerts.length },
      { name: t('benchmark.series.investigations'), value: benchmark?.pipeline.investigations ?? run.investigations.length },
      { name: t('benchmark.series.timeline'), value: benchmark?.pipeline.timelineEntries ?? run.timeline.length },
      { name: t('benchmark.series.nodes'), value: benchmark?.pipeline.graphNodes ?? run.entityGraph.nodes.length },
      { name: t('benchmark.series.edges'), value: benchmark?.pipeline.graphEdges ?? run.entityGraph.edges.length },
    ];

    return values;
  }, [benchmark, run.alerts.length, run.entityGraph.edges.length, run.entityGraph.nodes.length, run.investigations.length, run.normalizedEvents.length, run.timeline.length, t]);

  const graphDensity = useMemo(() => {
    const nodes = benchmark?.pipeline.graphNodes ?? run.entityGraph.nodes.length;
    const edges = benchmark?.pipeline.graphEdges ?? run.entityGraph.edges.length;
    if (!nodes) return '0.00';
    return (edges / nodes).toFixed(2);
  }, [benchmark, run.entityGraph.edges.length, run.entityGraph.nodes.length]);

  const sourcesCount = run.sources.length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('benchmark.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('benchmark.subtitle')}</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-lg border bg-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2"><Gauge className="h-4 w-4" /> {t('benchmark.release')}</div>
          <div className="font-mono text-xl font-bold mt-2">{health?.release || benchmark?.release || t('common.na')}</div>
          <div className="text-xs text-muted-foreground mt-1">{health?.package_version || benchmark?.packageVersion || t('common.na')}</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2"><DatabaseZap className="h-4 w-4" /> {t('benchmark.conversion')}</div>
          <div className="font-mono text-xl font-bold mt-2">{benchmark?.conversion.filesConverted ?? manifestSummary?.files_converted ?? 0}</div>
          <div className="text-xs text-muted-foreground mt-1">{t('benchmark.convertedFiles')}</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2"><Workflow className="h-4 w-4" /> {t('benchmark.pipeline')}</div>
          <div className="font-mono text-xl font-bold mt-2">{benchmark?.pipeline.rawEvents ?? run.normalizedEvents.length}</div>
          <div className="text-xs text-muted-foreground mt-1">{t('benchmark.eventsAnalyzed')}</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> EVTX</div>
          <div className="font-mono text-xl font-bold mt-2">{capabilities?.evtx_available ? t('common.ok') : 'NOK'}</div>
          <div className="text-xs text-muted-foreground mt-1">{t('benchmark.evtxDependency')}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="rounded-lg border bg-card p-4 space-y-4">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.releaseCheck')}</h2>
          <div className="space-y-2">
            {checks.map((item) => (
              <div key={item.label} className="rounded-lg border bg-muted/30 p-3 flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium">{item.label}</div>
                  <div className="text-xs text-muted-foreground">{item.detail}</div>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-mono ${item.ok ? 'bg-green-500/10 text-green-300 border border-green-400/30' : 'bg-amber-500/10 text-amber-300 border border-amber-400/30'}`}>
                  {item.ok ? t('common.ok') : t('benchmark.toHandle')}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border bg-card p-4 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.systemStats')}</h2>
              <p className="text-xs text-muted-foreground mt-1">{t('benchmark.systemStatsHint')}</p>
            </div>
            <Activity className="h-4 w-4 text-primary" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <Metric label={t('benchmark.observedRate')} value={formatRatePerMinute(benchmark?.pipeline.processingEventsPerMinute ?? 0)} icon={<Activity className="h-4 w-4" />} />
            <Metric label={t('benchmark.alertDensity')} value={density(run.alerts.length, run.normalizedEvents.length)} icon={<Gauge className="h-4 w-4" />} />
            <Metric label={t('benchmark.peakBucket')} value={`${peakBucket} evt`} icon={<Workflow className="h-4 w-4" />} />
            <Metric label={t('benchmark.graphDensity')} value={graphDensity} icon={<Network className="h-4 w-4" />} />
            <Metric label={t('benchmark.runtime')} value={formatSeconds(benchmark?.pipeline.runtimeSeconds ?? 0)} icon={<Activity className="h-4 w-4" />} />
            <Metric label={t('benchmark.incidentTempo')} value={formatRatePerMinute(benchmark?.incident.eventsPerMinute ?? 0)} icon={<Files className="h-4 w-4" />} />
            <Metric label={t('benchmark.artifactFootprint')} value={formatBytes(artifactFootprint)} icon={<HardDrive className="h-4 w-4" />} />
            <Metric label={t('benchmark.sourceCount')} value={sourcesCount} icon={<Files className="h-4 w-4" />} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1.25fr_0.95fr] gap-4">
        <div className="rounded-lg border bg-card p-4 space-y-4">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.activityCurve')}</h2>
            <p className="text-xs text-muted-foreground mt-1">{t('benchmark.activityCurveHint')}</p>
          </div>
          <div className="h-[280px]">
            {activitySeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">{t('benchmark.noRun')}</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activitySeries} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" />
                  <XAxis dataKey="bucket" tick={{ fontSize: 11 }} minTickGap={28} />
                  <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))' }} />
                  <Area type="monotone" dataKey="events" stroke="hsl(var(--primary))" fill="url(#activityFill)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="rounded-lg border bg-card p-4 space-y-4">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.pipelineShape')}</h2>
            <p className="text-xs text-muted-foreground mt-1">{t('benchmark.pipelineShapeHint')}</p>
          </div>
          <div className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={pipelineSeries} layout="vertical" margin={{ top: 8, right: 16, left: 12, bottom: 0 }}>
                <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} width={120} />
                <Tooltip contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))' }} />
                <Bar dataKey="value" fill="hsl(var(--primary))" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="rounded-lg border bg-card p-4 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.packagedSurface')}</h2>
          <div className="space-y-2 text-sm">
            <Row label={t('benchmark.guiMode')} value={capabilities?.gui_mode || 'integrated'} />
            <Row label={t('benchmark.outputDir')} value={health?.output_dir || t('common.na')} mono />
            <Row label={t('benchmark.lastRun')} value={run.timestamp ? formatTimestamp(run.timestamp) : t('benchmark.noRun')} />
            <Row label={t('benchmark.lastRefresh')} value={lastRefreshAt ? formatTimestamp(lastRefreshAt) : t('common.na')} />
            <Row label={t('benchmark.patientZero')} value={run.reconstruction.patientZero.entity || t('common.na')} mono />
            <Row label={t('benchmark.observationWindow')} value={timeStats.start && timeStats.end ? `${formatTimestamp(timeStats.start.toISOString())} → ${formatTimestamp(timeStats.end.toISOString())}` : t('common.na')} />
            <Row label={t('benchmark.runtime')} value={formatSeconds(benchmark?.pipeline.runtimeSeconds ?? 0)} />
            <Row label={t('benchmark.observedRate')} value={formatRatePerMinute(benchmark?.pipeline.processingEventsPerMinute ?? 0)} />
          </div>
        </div>

        <div className="rounded-lg border bg-card p-4 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('benchmark.availableArtifacts')}</h2>
          <div className="space-y-2 max-h-[260px] overflow-auto pr-1">
            {artifacts.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('benchmark.noArtifacts')}</p>
            ) : artifacts.map((artifact) => (
              <div key={artifact.name} className="rounded-lg border bg-muted/30 p-3 flex items-start gap-3">
                <Files className="h-4 w-4 mt-0.5 text-primary" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium truncate">{artifact.label}</div>
                  <div className="text-xs text-muted-foreground font-mono break-all">{artifact.name}</div>
                </div>
                <div className="text-[11px] text-muted-foreground font-mono whitespace-nowrap">{formatBytes(artifact.size_bytes)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: string | number; icon?: React.ReactNode }) {
  return (
    <div className="rounded-lg bg-muted/40 p-3 border border-border/50">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
        {icon ? <div className="text-primary/80">{icon}</div> : null}
      </div>
      <div className="font-mono text-lg font-bold mt-1">{value}</div>
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border/50 pb-2 last:border-0 last:pb-0">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? 'font-mono text-right break-all' : 'text-right'}>{value}</span>
    </div>
  );
}
