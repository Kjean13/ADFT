import React, { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { emptyRun, type AnalysisRun, type ProgressStep } from '@/engine/types';
import {
  exportScripts,
  fetchCapabilities,
  fetchHealth,
  fetchJob,
  fetchRun,
  triggerRefresh,
  jobToProgress,
  startConvert,
  startInvestigate,
  type ArtifactItem,
  type CapabilitiesPayload,
  type HealthPayload,
} from '@/lib/api';
import { useLanguage } from '@/context/LanguageContext';

interface ADFTContextValue {
  run: AnalysisRun & { artifacts?: ArtifactItem[]; rawState?: unknown };
  isRunning: boolean;
  isRefreshing: boolean;
  selectedFiles: File[];
  setSelectedFiles: (files: File[]) => void;
  startAnalysis: () => Promise<void>;
  startConversion: () => Promise<void>;
  loadRun: (run: AnalysisRun) => void;
  progress: ProgressStep[];
  conversionManifest: unknown;
  artifacts: ArtifactItem[];
  health: HealthPayload | null;
  capabilities: CapabilitiesPayload | null;
  lastRefreshAt: string | null;
  refresh: () => Promise<void>;
  exportHardeningScripts: () => Promise<void>;
  lastJobError: string | null;
}

const ADFTContext = createContext<ADFTContextValue | null>(null);

const SUPPORTED_EXTENSIONS = [
  '.json', '.jsonl', '.ndjson', '.evtx', '.yaml', '.yml', '.csv', '.tsv', '.cef', '.leef', '.xml', '.log', '.syslog', '.txt', '.md', '.markdown', '.zip',
];

function isSupported(file: File): boolean {
  const name = file.name.toLowerCase();
  return SUPPORTED_EXTENSIONS.some((ext) => name.endsWith(ext));
}

export function ADFTProvider({ children }: { children: ReactNode }) {
  const { language, t } = useLanguage();
  const [run, setRun] = useState<AnalysisRun & { artifacts?: ArtifactItem[]; rawState?: unknown }>(emptyRun as AnalysisRun & { artifacts?: ArtifactItem[]; rawState?: unknown });
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [progress, setProgress] = useState<ProgressStep[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [conversionManifest, setConversionManifest] = useState<unknown>(null);
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>([]);
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilitiesPayload | null>(null);
  const [lastRefreshAt, setLastRefreshAt] = useState<string | null>(null);
  const [lastJobError, setLastJobError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const refreshPayload = await triggerRefresh();
      const [runPayload, healthPayload, capabilitiesPayload] = await Promise.all([
        fetchRun(),
        fetchHealth(),
        fetchCapabilities(),
      ]);
      setRun(runPayload.run);
      setArtifacts(runPayload.artifacts || runPayload.run.artifacts || []);
      setConversionManifest(runPayload.conversion_manifest);
      setHealth(healthPayload);
      setCapabilities(capabilitiesPayload);
      setLastRefreshAt(refreshPayload.refreshed_at || new Date().toISOString());
      setLastJobError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setLastJobError(message);
      throw err;
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    refresh().catch((err) => {
      console.error('Failed to load backend state', err);
    });
  }, [language, refresh]);

  const pollJob = useCallback(async (jobId: string) => {
    while (true) {
      const job = await fetchJob(jobId);
      setProgress(jobToProgress(job, language));
      if (job.status === 'completed') {
        await refresh();
        setIsRunning(false);
        setLastJobError(null);
        return;
      }
      if (job.status === 'failed') {
        setIsRunning(false);
        setLastJobError(job.errors?.[0] || job.message || 'Job failed');
        throw new Error(job.errors?.[0] || job.message || 'Job failed');
      }
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  }, [language, refresh]);

  const startAnalysis = useCallback(async () => {
    const validFiles = selectedFiles.filter(isSupported);
    if (validFiles.length === 0 || isRunning) return;
    setIsRunning(true);
    setLastJobError(null);
    setProgress([{ label: t('stage.initialization'), status: 'running', detail: t('status.initializingAnalysis') }]);
    try {
      const { job_id } = await startInvestigate(validFiles, { export_events_jsonl: true, no_filter: false });
      await pollJob(job_id);
    } finally {
      setIsRunning(false);
    }
  }, [isRunning, pollJob, selectedFiles, t]);

  const startConversion = useCallback(async () => {
    const validFiles = selectedFiles.filter(isSupported);
    if (validFiles.length === 0 || isRunning) return;
    setIsRunning(true);
    setLastJobError(null);
    setProgress([{ label: t('stage.initialization'), status: 'running', detail: t('status.initializingConversion') }]);
    try {
      const { job_id } = await startConvert(validFiles);
      await pollJob(job_id);
    } finally {
      setIsRunning(false);
    }
  }, [isRunning, pollJob, selectedFiles, t]);

  const loadRun = useCallback((loaded: AnalysisRun) => {
    setRun(loaded);
  }, []);

  const exportHardeningScripts = useCallback(async () => {
    const result = await exportScripts();
    await refresh();
    window.open(result.download_url, '_blank', 'noopener,noreferrer');
  }, [language, refresh]);

  const value = useMemo<ADFTContextValue>(() => ({
    run,
    isRunning,
    isRefreshing,
    selectedFiles,
    setSelectedFiles,
    startAnalysis,
    startConversion,
    loadRun,
    progress,
    conversionManifest,
    artifacts,
    health,
    capabilities,
    lastRefreshAt,
    refresh,
    exportHardeningScripts,
    lastJobError,
  }), [artifacts, capabilities, conversionManifest, exportHardeningScripts, health, isRefreshing, isRunning, lastJobError, lastRefreshAt, loadRun, progress, refresh, run, selectedFiles, startAnalysis, startConversion]);

  return <ADFTContext.Provider value={value}>{children}</ADFTContext.Provider>;
}

export function useADFT() {
  const ctx = useContext(ADFTContext);
  if (!ctx) throw new Error('useADFT must be used within ADFTProvider');
  return ctx;
}
