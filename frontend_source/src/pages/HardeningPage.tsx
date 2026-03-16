import { useADFT } from '@/context/ADFTContext';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { Button } from '@/components/ui/button';
import { ShieldCheck, Download } from 'lucide-react';
import { difficultyLabel, useLanguage } from '@/context/LanguageContext';

export default function HardeningPage() {
  const { run, exportHardeningScripts, isRunning } = useADFT();
  const { language, t } = useLanguage();

  if (run.hardeningRecommendations.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">{t('hardening.title')}</h1>
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <ShieldCheck className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('hardening.empty')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-h-[85vh] overflow-auto">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">{t('hardening.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('hardening.subtitle', { count: run.hardeningRecommendations.length })}</p>
        </div>
        <Button variant="outline" onClick={() => exportHardeningScripts()} disabled={isRunning}>
          <Download className="h-4 w-4 mr-1" /> {t('hardening.exportScripts')}
        </Button>
      </div>

      <div className="space-y-3">
        {run.hardeningRecommendations.map((rec) => (
          <div key={rec.id} className="rounded-lg border bg-card p-4 space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="font-mono text-xs text-muted-foreground">{rec.id}</span>
              <SeverityBadge severity={rec.priority} />
              <span className="text-xs bg-muted px-2 py-0.5 rounded">{rec.category}</span>
              <span className="ml-auto text-xs">{difficultyLabel(language, rec.difficulty)}</span>
            </div>
            <h3 className="text-sm font-semibold">{rec.title}</h3>
            <p className="text-xs text-muted-foreground leading-relaxed">{rec.description}</p>
            <div className="text-xs">
              <span className="text-muted-foreground">{t('hardening.expectedImpact')}: </span>
              <span>{rec.expectedImpact}</span>
            </div>
            {rec.evidence.length > 0 && (
              <div>
                <span className="text-[10px] text-muted-foreground uppercase">{t('hardening.sourceEvidence')}</span>
                <div className="space-y-1 mt-1">
                  {rec.evidence.map((e, i) => (
                    <p key={i} className="text-[10px] font-mono text-muted-foreground break-words">{e}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
