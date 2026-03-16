import { useADFT } from '@/context/ADFTContext';
import { KPICard } from '@/components/forensic/KPICard';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { riskLabel, riskColor, formatTimestamp } from '@/lib/forensic-utils';
import { Shield, AlertTriangle, Search, Users, Monitor, Server, Network, Globe } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/context/LanguageContext';

export default function OverviewPage() {
  const { run } = useADFT();
  const { t } = useLanguage();
  const hasData = run.status === 'complete';

  const uniqueUsers = new Set(run.alerts.filter((a) => a.user !== 'N/A').map((a) => a.user)).size;
  const uniqueHosts = new Set(run.alerts.map((a) => a.host)).size;
  const uniqueIPs = new Set(run.alerts.filter((a) => a.ip !== 'N/A' && a.ip !== '-').map((a) => a.ip)).size;
  const lateralAlerts = run.alerts.filter((a) => a.mitreTactic === 'Lateral Movement').length;
  const criticalAssets = run.entityGraph.nodes.filter((n) => n.isCritical).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('overview.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('overview.subtitle')}</p>
      </div>

      {!hasData ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Shield className="h-16 w-16 mb-4 opacity-30" />
          <p className="text-lg">{t('overview.emptyTitle')}</p>
          <p className="text-sm">{t('overview.emptySubtitle')}</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KPICard
              label={t('overview.risk')}
              value={`${run.riskScore.global}/100`}
              icon={<Shield className="h-4 w-4" />}
              accent
              className={cn(riskColor(run.riskScore.global))}
            />
            <KPICard label={t('overview.alerts')} value={run.alerts.length} icon={<AlertTriangle className="h-4 w-4" />} />
            <KPICard label={t('overview.investigations')} value={run.investigations.length} icon={<Search className="h-4 w-4" />} />
            <KPICard label="AD Score" value={`${run.riskScore.adScore}/100`} icon={<Server className="h-4 w-4" />} />
            <KPICard label={t('overview.impactedAccounts')} value={uniqueUsers} icon={<Users className="h-4 w-4" />} />
            <KPICard label={t('overview.impactedHosts')} value={uniqueHosts} icon={<Monitor className="h-4 w-4" />} />
            <KPICard label={t('overview.lateralPaths')} value={lateralAlerts} icon={<Network className="h-4 w-4" />} />
            <KPICard label={t('overview.sourceIps')} value={uniqueIPs} icon={<Globe className="h-4 w-4" />} />
          </div>

          {criticalAssets > 0 && (
            <div className="rounded-lg border border-severity-critical/30 bg-severity-critical/5 p-4">
              <p className="text-severity-critical font-semibold text-sm">{t('overview.criticalAssets', { count: criticalAssets })}</p>
            </div>
          )}

          <div className="rounded-lg border bg-card p-4">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">{t('overview.execSummary')}</h2>
            <p className="text-sm leading-relaxed">
              {t('overview.execText', {
                events: run.normalizedEvents.length,
                sources: run.sources.length,
                alerts: run.alerts.length,
                critical: run.alerts.filter((a) => a.severity === 'critical').length,
                investigations: run.investigations.length,
                risk: '___RISK___',
              }).split('___RISK___')[0]}
              <span className={cn('font-bold', riskColor(run.riskScore.global))}>{riskLabel(run.riskScore.global)}</span>
              {t('overview.execText', {
                events: run.normalizedEvents.length,
                sources: run.sources.length,
                alerts: run.alerts.length,
                critical: run.alerts.filter((a) => a.severity === 'critical').length,
                investigations: run.investigations.length,
                risk: '___RISK___',
              }).split('___RISK___').slice(1).join('___RISK___')}
            </p>
          </div>

          <div className="rounded-lg border bg-card p-4">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">{t('overview.topAlerts')}</h2>
            <div className="space-y-2">
              {run.alerts.slice(0, 10).map((alert) => (
                <div key={alert.id} className="flex items-center gap-3 text-sm py-1.5 border-b border-border/50 last:border-0">
                  <SeverityBadge severity={alert.severity} />
                  <span className="font-mono text-xs text-muted-foreground">{alert.id}</span>
                  <span className="flex-1 truncate">{alert.ruleName}</span>
                  <span className="text-xs text-muted-foreground font-mono">{alert.mitreId}</span>
                  <span className="text-xs text-muted-foreground">{formatTimestamp(alert.timestamp)}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
