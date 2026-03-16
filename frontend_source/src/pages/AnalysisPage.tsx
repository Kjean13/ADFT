import React, { useCallback, useMemo, useRef } from 'react';
import { useADFT } from '@/context/ADFTContext';
import { Button } from '@/components/ui/button';
import { FolderOpen, FileText, Play, RefreshCw, WandSparkles, X, CheckCircle2, XCircle, Loader2, Clock, AlertTriangle, ShieldCheck, Database } from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatTimestamp } from '@/lib/forensic-utils';
import { useLanguage } from '@/context/LanguageContext';
import { toast } from '@/hooks/use-toast';

const VALID_EXTENSIONS = ['.json', '.jsonl', '.ndjson', '.evtx', '.yaml', '.yml', '.csv', '.tsv', '.cef', '.leef', '.xml', '.log', '.syslog', '.txt', '.md', '.markdown', '.zip'];

export default function AnalysisPage() {
  const {
    selectedFiles,
    setSelectedFiles,
    startAnalysis,
    startConversion,
    isRunning,
    isRefreshing,
    progress,
    run,
    conversionManifest,
    refresh,
    lastJobError,
    health,
    capabilities,
    lastRefreshAt,
    artifacts,
  } = useADFT();
  const { t } = useLanguage();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const existing = new Map(selectedFiles.map((file) => [file.name + file.size, file]));
      Array.from(e.target.files).forEach((file) => existing.set(file.name + file.size, file));
      setSelectedFiles(Array.from(existing.values()));
    }
  }, [selectedFiles, setSelectedFiles]);

  const removeFile = (index: number) => {
    setSelectedFiles(selectedFiles.filter((_, i) => i !== index));
  };

  const validFiles = useMemo(() => selectedFiles.filter((file) => VALID_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))), [selectedFiles]);
  const invalidFiles = useMemo(() => selectedFiles.filter((file) => !VALID_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))), [selectedFiles]);
  const manifestSummary = (conversionManifest as { summary?: Record<string, number> } | null)?.summary || null;

  const handleRefresh = useCallback(async () => {
    try {
      await refresh();
      toast({ title: t('common.refresh'), description: t('analysis.refreshOk') });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      toast({ title: t('analysis.refreshError'), description: message, variant: 'destructive' });
    }
  }, [refresh, t]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('analysis.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('analysis.subtitle')}</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="rounded-lg border bg-card p-4 space-y-4">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('analysis.sources')}</h3>
            <p className="text-xs text-muted-foreground mt-1">{t('analysis.supportedFormats')}</p>
          </div>

          <div className="flex gap-2 flex-wrap">
            <input ref={fileInputRef} type="file" multiple className="hidden" onChange={handleFileSelect} />
            <input ref={folderInputRef} type="file" multiple {...({ webkitdirectory: 'true', directory: 'true' } as React.InputHTMLAttributes<HTMLInputElement>)} className="hidden" onChange={handleFileSelect} />

            <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()} disabled={isRunning || isRefreshing}>
              <FileText className="h-4 w-4 mr-1" /> {t('analysis.files')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => folderInputRef.current?.click()} disabled={isRunning || isRefreshing}>
              <FolderOpen className="h-4 w-4 mr-1" /> {t('analysis.folder')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setSelectedFiles([])} disabled={isRunning || isRefreshing || selectedFiles.length === 0}>
              <X className="h-4 w-4 mr-1" /> {t('analysis.clear')}
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isRunning || isRefreshing}>
              {isRefreshing ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
              {t('analysis.refresh')}
            </Button>
          </div>

          <div className="space-y-1 max-h-72 overflow-auto rounded-lg border bg-background/30 p-2">
            {selectedFiles.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">{t('analysis.noFiles')}</p>
            ) : (
              selectedFiles.map((file, i) => {
                const isValid = VALID_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext));
                return (
                  <div key={`${file.name}-${i}`} className={cn('flex items-center gap-2 text-xs py-1 px-2 rounded', isValid ? 'bg-muted/50' : 'bg-destructive/10')}>
                    {isValid ? <CheckCircle2 className="h-3 w-3 text-green-400 flex-shrink-0" /> : <XCircle className="h-3 w-3 text-destructive flex-shrink-0" />}
                    <span className="flex-1 truncate font-mono">{file.name}</span>
                    <span className="text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</span>
                    <button onClick={() => removeFile(i)} disabled={isRunning || isRefreshing} className="text-muted-foreground hover:text-foreground">
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                );
              })
            )}
          </div>

          {invalidFiles.length > 0 && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
              {t('analysis.unsupported', { count: invalidFiles.length })}
            </div>
          )}

          <div className="flex gap-2 flex-wrap">
            <Button variant="outline" onClick={startConversion} disabled={validFiles.length === 0 || isRunning || isRefreshing}>
              {isRunning ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <WandSparkles className="h-4 w-4 mr-1" />}
              {t('analysis.convertOnly')}
            </Button>
            <Button onClick={startAnalysis} disabled={validFiles.length === 0 || isRunning || isRefreshing} className="flex-1 min-w-[180px]">
              {isRunning ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              {t('analysis.fullAnalysis')}
            </Button>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border bg-card p-4 space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('analysis.progress')}</h3>
            <div className="space-y-2 font-mono text-xs">
              {progress.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center">{t('analysis.waiting')}</p>
              ) : (
                progress.map((step, i) => (
                  <div key={`${step.label}-${i}`} className={cn('flex items-center gap-2 py-1', step.status === 'error' && 'text-destructive')}>
                    {step.status === 'done' && <CheckCircle2 className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />}
                    {step.status === 'running' && <Loader2 className="h-3.5 w-3.5 text-primary animate-spin flex-shrink-0" />}
                    {step.status === 'pending' && <Clock className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
                    {step.status === 'error' && <XCircle className="h-3.5 w-3.5 text-destructive flex-shrink-0" />}
                    <span>{step.label}</span>
                    {step.detail && <span className="text-muted-foreground ml-auto truncate max-w-[45%]">{step.detail}</span>}
                  </div>
                ))
              )}
            </div>
            {lastJobError && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive flex gap-2">
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span>{lastJobError}</span>
              </div>
            )}
          </div>

          <div className="rounded-lg border bg-card p-4 space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('analysis.backendState')}</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div className="rounded-md bg-muted/40 p-3 space-y-1">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.release')}</div>
                <div className="font-mono text-sm font-semibold">{health?.release || t('common.na')} / {health?.package_version || t('common.na')}</div>
              </div>
              <div className="rounded-md bg-muted/40 p-3 space-y-1">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.evtx')}</div>
                <div className="font-mono text-sm font-semibold flex items-center gap-2">
                  <ShieldCheck className={cn('h-4 w-4', capabilities?.evtx_available ? 'text-green-400' : 'text-amber-400')} />
                  {capabilities?.evtx_available ? t('analysis.evtxAvailable') : t('analysis.evtxMissing')}
                </div>
              </div>
              <div className="rounded-md bg-muted/40 p-3 space-y-1 md:col-span-2">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.lastRefresh')}</div>
                <div className="font-mono text-xs">{lastRefreshAt ? formatTimestamp(lastRefreshAt) : t('analysis.never')}</div>
              </div>
              <div className="rounded-md bg-muted/40 p-3 space-y-1 md:col-span-2">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.outputDir')}</div>
                <div className="font-mono text-xs break-all">{health?.output_dir || t('common.na')}</div>
              </div>
            </div>
          </div>

          <div className="rounded-lg border bg-card p-4 space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('analysis.lastEngineResult')}</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.eventsAnalyzed')}</div><div className="font-mono text-xl font-bold">{run.normalizedEvents.length}</div></div>
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.alertsCount')}</div><div className="font-mono text-xl font-bold">{run.alerts.length}</div></div>
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.investigationsCount')}</div><div className="font-mono text-xl font-bold">{run.investigations.length}</div></div>
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">Observed risk</div><div className="font-mono text-xl font-bold">{run.riskScore.global || 0}</div></div>
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.graphNodes')}</div><div className="font-mono text-xl font-bold">{run.entityGraph.nodes.length}</div></div>
              <div className="rounded-md bg-muted/40 p-3"><div className="text-[10px] uppercase tracking-wide text-muted-foreground">{t('analysis.graphEdges')}</div><div className="font-mono text-xl font-bold">{run.entityGraph.edges.length}</div></div>
            </div>
          </div>

          <div className="rounded-lg border bg-card p-4 space-y-2">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
              <Database className="h-4 w-4" /> {t('analysis.canonicalManifest')}
            </h3>
            {manifestSummary ? (
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div><span className="text-muted-foreground">{t('analysis.filesScanned')}: </span><span className="font-mono">{manifestSummary.files_scanned ?? 0}</span></div>
                <div><span className="text-muted-foreground">{t('analysis.filesConverted')}: </span><span className="font-mono">{manifestSummary.files_converted ?? 0}</span></div>
                <div><span className="text-muted-foreground">{t('analysis.filesFailed')}: </span><span className="font-mono">{manifestSummary.files_failed ?? 0}</span></div>
                <div><span className="text-muted-foreground">{t('analysis.filesSkipped')}: </span><span className="font-mono">{manifestSummary.files_skipped ?? 0}</span></div>
                <div className="col-span-2"><span className="text-muted-foreground">{t('analysis.eventsWritten')}: </span><span className="font-mono">{manifestSummary.events_written ?? 0}</span></div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">{t('analysis.noManifest')}</p>
            )}
          </div>

          <div className="rounded-lg border bg-card p-4 space-y-2">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">{t('analysis.artifacts')}</h3>
            {artifacts.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t('analysis.noArtifacts')}</p>
            ) : (
              <div className="space-y-2 max-h-48 overflow-auto">
                {artifacts.map((artifact) => (
                  <div key={artifact.name} className="rounded border bg-muted/30 px-3 py-2 text-xs flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate font-medium">{artifact.label}</div>
                      <div className="truncate text-muted-foreground font-mono">{artifact.name}</div>
                    </div>
                    <div className="text-right text-muted-foreground whitespace-nowrap">{t('analysis.generatedAt')}<br />{formatTimestamp(new Date(artifact.created_at * 1000).toISOString())}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
