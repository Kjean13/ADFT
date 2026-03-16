import { useState } from 'react';
import { useADFT } from '@/context/ADFTContext';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { Investigation } from '@/engine/types';
import { Search, X } from 'lucide-react';
import { entityTypeLabel, useLanguage } from '@/context/LanguageContext';

export default function InvestigationsPage() {
  const { run } = useADFT();
  const { language, t } = useLanguage();
  const [selected, setSelected] = useState<Investigation | null>(null);

  if (run.investigations.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">{t('investigations.title')}</h1>
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Search className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('investigations.empty')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 h-full flex flex-col">
      <h1 className="text-2xl font-bold">{t('investigations.title')}</h1>

      <div className="flex-1 flex gap-4 min-h-0">
        <div className="w-96 overflow-auto space-y-2 flex-shrink-0">
          {run.investigations.map((inv) => (
            <div
              key={inv.id}
              onClick={() => setSelected(inv)}
              className={`rounded-lg border bg-card p-3 cursor-pointer hover:bg-muted/50 space-y-1 ${selected?.id === inv.id ? 'glow-border' : ''}`}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">{inv.id}</span>
                <SeverityBadge severity={inv.severity} />
                <span className="ml-auto font-mono text-sm font-bold text-primary">{inv.score}</span>
              </div>
              <p className="text-sm truncate">{inv.title}</p>
              <p className="text-xs text-muted-foreground truncate">{inv.hypothesis}</p>
              <div className="flex gap-1 flex-wrap">
                {inv.entities.slice(0, 4).map((e, i) => (
                  <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-muted font-mono">
                    {entityTypeLabel(language, e.type)}: {e.value}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        {selected ? (
          <div className="flex-1 rounded-lg border bg-card p-4 overflow-auto space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold">{selected.id}</h2>
                <SeverityBadge severity={selected.severity} />
              </div>
              <button onClick={() => setSelected(null)}><X className="h-4 w-4 text-muted-foreground" /></button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div><span className="text-muted-foreground text-xs">{t('investigations.score')}:</span><p className="font-mono text-xl font-bold text-primary">{selected.score}/100</p></div>
              <div><span className="text-muted-foreground text-xs">{t('investigations.linkedAlerts')}:</span><p className="font-mono">{selected.alerts.length}</p></div>
            </div>

            <div>
              <h3 className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{t('investigations.hypothesis')}</h3>
              <p className="text-sm">{selected.hypothesis}</p>
            </div>

            <div>
              <h3 className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{t('investigations.analystSummary')}</h3>
              <p className="text-sm bg-muted/50 p-3 rounded">{selected.analystSummary}</p>
            </div>

            <div>
              <h3 className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{t('investigations.managerSummary')}</h3>
              <p className="text-sm bg-muted/50 p-3 rounded">{selected.managerSummary}</p>
            </div>

            <div>
              <h3 className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{t('investigations.entities')}</h3>
              <div className="flex gap-2 flex-wrap">
                {selected.entities.map((e, i) => (
                  <span key={i} className="text-xs px-2 py-1 rounded bg-muted font-mono">{entityTypeLabel(language, e.type)}: {e.value}</span>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{t('investigations.linkedAlerts')}</h3>
              <div className="space-y-1">
                {selected.alerts.map((aId) => {
                  const alert = run.alerts.find((a) => a.id === aId);
                  if (!alert) return null;
                  return (
                    <div key={aId} className="flex items-center gap-2 text-xs py-1 border-b border-border/30">
                      <SeverityBadge severity={alert.severity} />
                      <span className="font-mono">{alert.id}</span>
                      <span className="truncate flex-1">{alert.ruleName}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
            {t('investigations.select')}
          </div>
        )}
      </div>
    </div>
  );
}
