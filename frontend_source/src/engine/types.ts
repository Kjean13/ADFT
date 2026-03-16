// Core types for ADFT engine

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface RawEvent {
  [key: string]: unknown;
}

export interface NormalizedEvent {
  id: string;
  timestamp: string;
  eventId: number;
  source: string;
  channel: string;
  computer: string;
  user: string;
  ip: string;
  process: string;
  logonType?: number;
  status?: string;
  targetUser?: string;
  targetDomain?: string;
  serviceName?: string;
  taskCategory?: string;
  message: string;
  raw: RawEvent;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  mitreTactic: string;
  mitreId: string;
  match: (event: NormalizedEvent) => boolean;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  mitreTactic: string;
  mitreId: string;
  timestamp: string;
  host: string;
  user: string;
  ip: string;
  description: string;
  eventId: string;
  investigationId?: string;
  event: NormalizedEvent;
}

export interface Investigation {
  id: string;
  title: string;
  severity: Severity;
  score: number;
  hypothesis: string;
  analystSummary: string;
  managerSummary: string;
  entities: EntityRef[];
  alerts: string[];
  createdAt: string;
}

export interface EntityRef {
  type: 'user' | 'host' | 'ip' | 'process' | 'service' | 'ad_object';
  value: string;
}

export interface TimelineEntry {
  id: string;
  timestamp: string;
  type: 'event' | 'alert' | 'investigation';
  severity: Severity;
  title: string;
  description: string;
  entities: EntityRef[];
  sourceId: string;
}

export interface EntityNode {
  id: string;
  type: EntityRef['type'];
  label: string;
  risk: number;
  alertCount: number;
  isCritical: boolean;
  firstSeen?: string | null;
  lastSeen?: string | null;
  isKnownIoc?: boolean;
  degree?: number;
  role?: string;
  clusterSize?: number;
}

export interface EntityEdge {
  source: string;
  target: string;
  label: string;
  weight: number;
  relation?: string;
  firstSeen?: string | null;
  lastSeen?: string | null;
}

export interface EntityGraph {
  nodes: EntityNode[];
  edges: EntityEdge[];
  mermaid?: string;
  timeframe?: { start: string; end: string };
  summary?: {
    nodes: number;
    edges: number;
    accounts?: number;
    hosts?: number;
    ips?: number;
    domainControllers?: number;
    privilegedAccounts?: number;
    hotNodes?: number;
  };
  analysis?: Record<string, unknown>;
}

export interface RiskScore {
  global: number;
  adScore: number;
  breakdown: {
    category: string;
    score: number;
    weight: number;
    details: string;
  }[];
  summary?: string;
  riskLevel?: string;
}

export interface HardeningRecommendation {
  id: string;
  title: string;
  description: string;
  priority: Severity;
  difficulty: 'easy' | 'medium' | 'hard';
  expectedImpact: string;
  evidence: string[];
  category: string;
}

export interface AttackReconstruction {
  story: string;
  attackChain: { step: number; phase: string; description: string; mitre: string; timestamp: string }[];
  attackPath: string[];
  patientZero: { entity: string; confidence: number; evidence: string };
  estimatedImpacts: { area: string; severity: Severity; description: string }[];
}

export interface BenchmarkSnapshot {
  release: string;
  packageVersion: string;
  supportedInputs: string[];
  evtxAvailable: boolean;
  conversion: {
    filesScanned: number;
    filesConverted: number;
    filesFailed: number;
    filesSkipped: number;
    eventsWritten: number;
  };
  pipeline: {
    rawEvents: number;
    detections: number;
    alerts: number;
    investigations: number;
    timelineEntries: number;
    graphNodes: number;
    graphEdges: number;
    artifacts: number;
    runtimeSeconds: number;
    processingEventsPerSecond: number;
    processingEventsPerMinute: number;
  };
  incident: {
    start: string;
    end: string;
    spanSeconds: number;
    eventsPerMinute: number;
  };
}

export interface AnalysisRun {
  id: string;
  timestamp: string;
  sources: string[];
  normalizedEvents: NormalizedEvent[];
  alerts: Alert[];
  investigations: Investigation[];
  timeline: TimelineEntry[];
  entityGraph: EntityGraph;
  riskScore: RiskScore;
  hardeningRecommendations: HardeningRecommendation[];
  reconstruction: AttackReconstruction;
  benchmark?: BenchmarkSnapshot;
  status: 'idle' | 'running' | 'complete' | 'error';
  progress: ProgressStep[];
  error?: string;
}

export interface ProgressStep {
  label: string;
  status: 'pending' | 'running' | 'done' | 'error';
  detail?: string;
}

export const emptyRun: AnalysisRun = {
  id: '',
  timestamp: '',
  sources: [],
  normalizedEvents: [],
  alerts: [],
  investigations: [],
  timeline: [],
  entityGraph: { nodes: [], edges: [] },
  riskScore: { global: 0, adScore: 0, breakdown: [] },
  hardeningRecommendations: [],
  reconstruction: {
    story: '',
    attackChain: [],
    attackPath: [],
    patientZero: { entity: '', confidence: 0, evidence: '' },
    estimatedImpacts: [],
  },
  benchmark: undefined,
  status: 'idle',
  progress: [],
};
