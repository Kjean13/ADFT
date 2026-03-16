import type { AnalysisRun, ProgressStep } from '@/engine/types';
import { translateForLanguage, type Language } from '@/context/LanguageContext';

export interface HealthPayload {
  status: string;
  release: string;
  package_version: string;
  output_dir: string;
  current_run_available: boolean;
  artifacts: number;
}

export interface CapabilitiesPayload {
  release: string;
  package_version: string;
  supported_inputs: string[];
  commands: string[];
  gui_mode: string;
  evtx_available: boolean;
}

export interface ArtifactItem {
  name: string;
  label: string;
  size_bytes: number;
  created_at: number;
  download_url: string;
  preview_url?: string | null;
}

export interface RunPayload {
  run: AnalysisRun & { artifacts?: ArtifactItem[]; rawState?: unknown };
  artifacts: ArtifactItem[];
  conversion_manifest: unknown;
}


export interface RefreshPayload {
  status: string;
  refreshed_at: string;
  current_run_available: boolean;
  artifacts: number;
}

export interface JobPayload {
  job_id: string;
  kind: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  stage: string;
  progress_pct: number;
  message: string;
  started_at?: number | null;
  finished_at?: number | null;
  errors: string[];
  result?: Record<string, unknown> | null;
}

const API_BASE = '';

function withCacheBust(path: string): string {
  const sep = path.includes('?') ? '&' : '?';
  return `${API_BASE}${path}${sep}_ts=${Date.now()}`;
}

async function expectJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchHealth(): Promise<HealthPayload> {
  return expectJson<HealthPayload>(await fetch(withCacheBust('/api/health'), { cache: 'no-store' }));
}

export async function fetchCapabilities(): Promise<CapabilitiesPayload> {
  return expectJson<CapabilitiesPayload>(await fetch(withCacheBust('/api/capabilities'), { cache: 'no-store' }));
}

export async function fetchRun(): Promise<RunPayload> {
  return expectJson<RunPayload>(await fetch(withCacheBust('/api/run'), { cache: 'no-store' }));
}

export async function triggerRefresh(): Promise<RefreshPayload> {
  return expectJson<RefreshPayload>(await fetch(`${API_BASE}/api/refresh`, { method: 'POST', cache: 'no-store' }));
}

export async function fetchJob(jobId: string): Promise<JobPayload> {
  return expectJson<JobPayload>(await fetch(withCacheBust(`/api/jobs/${jobId}`), { cache: 'no-store' }));
}

async function upload(endpoint: '/api/convert' | '/api/investigate', files: File[], options?: Record<string, string | boolean>): Promise<{ job_id: string }> {
  const body = new FormData();
  files.forEach((file) => body.append('files', file, file.name));
  Object.entries(options || {}).forEach(([key, value]) => body.append(key, String(value)));
  return expectJson<{ job_id: string }>(await fetch(`${API_BASE}${endpoint}`, { method: 'POST', body, cache: 'no-store' }));
}

export async function startConvert(files: File[]): Promise<{ job_id: string }> {
  return upload('/api/convert', files);
}

export async function startInvestigate(files: File[], options?: { export_events_jsonl?: boolean; no_filter?: boolean }): Promise<{ job_id: string }> {
  return upload('/api/investigate', files, {
    export_events_jsonl: options?.export_events_jsonl ?? true,
    no_filter: options?.no_filter ?? false,
  });
}

export async function exportScripts(): Promise<{ artifact: string; download_url: string; path: string }> {
  return expectJson(await fetch(`${API_BASE}/api/export-scripts`, { method: 'POST', cache: 'no-store' }));
}

export function artifactUrl(name: string): string {
  return `${API_BASE}/api/artifacts/${encodeURIComponent(name)}`;
}

export function jobToProgress(job: JobPayload, language: Language = 'fr'): ProgressStep[] {
  const stages = [
    'conversion',
    'ingestion',
    'normalization',
    'detection',
    'correlation',
    'timeline',
    'entity_graph',
    'risk_scoring',
    'hardening',
    'reporting',
    'exports',
  ];

  let reachedCurrent = false;
  return stages.map((stage) => {
    const label = translateForLanguage(language, `stage.${stage}`);
    if (job.status === 'failed' && job.stage === stage) {
      return { label, status: 'error' as const, detail: job.errors[0] || job.message };
    }
    if (job.status === 'completed') {
      return { label, status: 'done' as const };
    }
    if (job.stage === stage) {
      reachedCurrent = true;
      return { label, status: 'running' as const, detail: job.message };
    }
    if (!reachedCurrent && job.progress_pct > 0) {
      return { label, status: 'done' as const };
    }
    return { label, status: 'pending' as const };
  });
}
