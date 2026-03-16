import { useState, useMemo } from 'react';
import { useADFT } from '@/context/ADFTContext';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { formatTimestamp } from '@/lib/forensic-utils';
import { Alert, Severity } from '@/engine/types';
import { Input } from '@/components/ui/input';
import { Shield, X } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export default function AlertsPage() {
  const { run } = useADFT();
  const { t } = useLanguage();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [selected, setSelected] = useState<Alert | null>(null);

  const filtered = useMemo(() => {
    return run.alerts.filter((a) => {
      if (severityFilter && a.severity !== severityFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return (
          a.id.toLowerCase().includes(s) ||
          a.ruleName.toLowerCase().includes(s) ||
          a.user.toLowerCase().includes(s) ||
          a.host.toLowerCase().includes(s) ||
          a.ip.toLowerCase().includes(s) ||
          a.mitreId.toLowerCase().includes(s)
        );
      }
      return true;
    });
  }, [run.alerts, search, severityFilter]);

  const hasData = run.alerts.length > 0;
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div>
        <h1 className="text-2xl font-bold">{t('alerts.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('alerts.detected', { count: run.alerts.length })}</p>
      </div>

      {!hasData ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Shield className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('alerts.empty')}</p>
        </div>
      ) : (
        <>
          <div className="flex gap-2 flex-wrap">
            <Input placeholder={t('alerts.search')} value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-xs h-8 text-sm bg-muted border-border" />
            {severities.map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(severityFilter === s ? '' : s)}
                className={`px-2 py-1 rounded text-xs font-mono uppercase ${severityFilter === s ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground hover:text-foreground'}`}
              >
                {s} ({run.alerts.filter((a) => a.severity === s).length})
              </button>
            ))}
          </div>

          <div className="flex-1 flex gap-4 min-h-0">
            <div className="flex-1 overflow-auto rounded-lg border bg-card">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface-2">
                  <tr className="text-muted-foreground uppercase tracking-wider">
                    <th className="p-2 text-left">{t('alerts.id')}</th>
                    <th className="p-2 text-left">{t('alerts.severity')}</th>
                    <th className="p-2 text-left">{t('alerts.rule')}</th>
                    <th className="p-2 text-left">{t('alerts.mitre')}</th>
                    <th className="p-2 text-left">{t('alerts.host')}</th>
                    <th className="p-2 text-left">{t('alerts.user')}</th>
                    <th className="p-2 text-left">{t('alerts.ip')}</th>
                    <th className="p-2 text-left">{t('alerts.date')}</th>
                    <th className="p-2 text-left">{t('alerts.investigation')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => setSelected(alert)}
                      className={`border-b border-border/30 cursor-pointer hover:bg-muted/50 ${selected?.id === alert.id ? 'bg-primary/10' : ''}`}
                    >
                      <td className="p-2 font-mono">{alert.id}</td>
                      <td className="p-2"><SeverityBadge severity={alert.severity} /></td>
                      <td className="p-2 max-w-[200px] truncate">{alert.ruleName}</td>
                      <td className="p-2 font-mono">{alert.mitreId}</td>
                      <td className="p-2 font-mono">{alert.host}</td>
                      <td className="p-2 font-mono">{alert.user}</td>
                      <td className="p-2 font-mono">{alert.ip}</td>
                      <td className="p-2">{formatTimestamp(alert.timestamp)}</td>
                      <td className="p-2 font-mono text-primary">{alert.investigationId || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selected && (
              <div className="w-80 rounded-lg border bg-card p-4 overflow-auto space-y-3 flex-shrink-0">
                <div className="flex items-center justify-between">
                  <h3 className="font-mono text-sm font-bold">{selected.id}</h3>
                  <button onClick={() => setSelected(null)}><X className="h-4 w-4 text-muted-foreground" /></button>
                </div>
                <SeverityBadge severity={selected.severity} />
                <div className="space-y-2 text-xs">
                  <div><span className="text-muted-foreground">{t('alerts.rule')}:</span> {selected.ruleName}</div>
                  <div><span className="text-muted-foreground">{t('alerts.description')}:</span> {selected.description}</div>
                  <div><span className="text-muted-foreground">{t('alerts.mitre')}:</span> {selected.mitreId} — {selected.mitreTactic}</div>
                  <div><span className="text-muted-foreground">{t('alerts.host')}:</span> <span className="font-mono">{selected.host}</span></div>
                  <div><span className="text-muted-foreground">{t('alerts.user')}:</span> <span className="font-mono">{selected.user}</span></div>
                  <div><span className="text-muted-foreground">{t('alerts.ip')}:</span> <span className="font-mono">{selected.ip}</span></div>
                  <div><span className="text-muted-foreground">{t('alerts.date')}:</span> {formatTimestamp(selected.timestamp)}</div>
                  <div><span className="text-muted-foreground">{t('alerts.investigation')}:</span> <span className="font-mono text-primary">{selected.investigationId || t('alerts.unassigned')}</span></div>
                  <div className="pt-2 border-t">
                    <span className="text-muted-foreground">{t('alerts.sourceEvent')}:</span>
                    <pre className="mt-1 bg-muted p-2 rounded text-[10px] overflow-auto max-h-40 font-mono">
                      {JSON.stringify(selected.event.raw, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
