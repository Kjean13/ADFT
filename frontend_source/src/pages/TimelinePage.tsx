import { useState, useMemo } from 'react';
import { useADFT } from '@/context/ADFTContext';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { formatTimestamp } from '@/lib/forensic-utils';
import { Input } from '@/components/ui/input';
import { Clock } from 'lucide-react';
import { Severity as SeverityType } from '@/engine/types';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/context/LanguageContext';

export default function TimelinePage() {
  const { run } = useADFT();
  const { t } = useLanguage();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityType | ''>('');

  const filtered = useMemo(() => {
    return run.timeline.filter((entry) => {
      if (severityFilter && entry.severity !== severityFilter) return false;
      if (search) {
        const s = search.toLowerCase();
        return entry.title.toLowerCase().includes(s) || entry.description.toLowerCase().includes(s) || entry.entities.some((e) => e.value.toLowerCase().includes(s));
      }
      return true;
    });
  }, [run.timeline, search, severityFilter]);

  if (run.timeline.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">{t('timeline.title')}</h1>
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Clock className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('timeline.empty')}</p>
        </div>
      </div>
    );
  }

  const typeColors: Record<string, string> = {
    alert: 'border-l-severity-high',
    event: 'border-l-primary',
    investigation: 'border-l-severity-critical',
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t('timeline.title')}</h1>

      <div className="flex gap-2 flex-wrap">
        <Input placeholder={t('timeline.filter')} value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-xs h-8 text-sm bg-muted" />
        {(['critical', 'high', 'medium', 'low', 'info'] as SeverityType[]).map((s) => (
          <button key={s} onClick={() => setSeverityFilter(severityFilter === s ? '' : s)} className={`px-2 py-1 rounded text-xs font-mono uppercase ${severityFilter === s ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground hover:text-foreground'}`}>
            {s}
          </button>
        ))}
      </div>

      <div className="space-y-1 max-h-[70vh] overflow-auto">
        {filtered.map((entry) => (
          <div key={entry.id} className={cn('border-l-2 pl-4 py-2 bg-card rounded-r-lg', typeColors[entry.type] || 'border-l-border')}>
            <div className="flex items-center gap-2 text-xs">
              <span className="font-mono text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
              <SeverityBadge severity={entry.severity} />
              <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] uppercase font-mono">{t(`timeline.${entry.type}`)}</span>
            </div>
            <p className="text-sm font-medium mt-1">{entry.title}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{entry.description}</p>
            {entry.entities.length > 0 && (
              <div className="flex gap-1 mt-1 flex-wrap">
                {entry.entities.map((e, i) => (
                  <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-muted font-mono">{e.type}:{e.value}</span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
