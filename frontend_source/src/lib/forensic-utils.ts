import { Severity } from '@/engine/types';

export function severityColor(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'text-severity-critical',
    high: 'text-severity-high',
    medium: 'text-severity-medium',
    low: 'text-severity-low',
    info: 'text-severity-info',
  };
  return map[severity];
}

export function severityBg(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'bg-severity-critical',
    high: 'bg-severity-high',
    medium: 'bg-severity-medium',
    low: 'bg-severity-low',
    info: 'bg-severity-info',
  };
  return map[severity];
}

export function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function riskLabel(score: number): string {
  if (score <= 25) return 'CRITICAL';
  if (score <= 50) return 'HIGH';
  if (score <= 75) return 'MEDIUM';
  return 'LOW';
}

export function riskColor(score: number): string {
  if (score <= 25) return 'text-severity-critical';
  if (score <= 50) return 'text-severity-high';
  if (score <= 75) return 'text-severity-medium';
  return 'text-severity-low';
}
