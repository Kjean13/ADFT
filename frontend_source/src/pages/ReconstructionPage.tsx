import { useADFT } from '@/context/ADFTContext';
import { SeverityBadge } from '@/components/forensic/SeverityBadge';
import { Swords, ArrowRight } from 'lucide-react';
import { useLanguage } from '@/context/LanguageContext';

export default function ReconstructionPage() {
  const { run } = useADFT();
  const { t } = useLanguage();
  const { reconstruction } = run;

  if (!reconstruction.story || reconstruction.attackChain.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">{t('reconstruction.title')}</h1>
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Swords className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('reconstruction.empty')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-h-[85vh] overflow-auto">
      <h1 className="text-2xl font-bold">{t('reconstruction.attackTitle')}</h1>

      <div className="rounded-lg border bg-card p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">{t('reconstruction.chain')}</h2>
        <div className="flex items-start gap-2 overflow-x-auto pb-2">
          {reconstruction.attackChain.map((step, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="min-w-[180px] rounded-lg border bg-muted p-3 space-y-1">
                <div className="text-[10px] text-muted-foreground uppercase">{t('reconstruction.step', { step: step.step })}</div>
                <div className="text-sm font-bold text-primary">{step.phase}</div>
                <div className="text-xs text-muted-foreground font-mono">{step.mitre}</div>
                <div className="text-xs">{step.description}</div>
              </div>
              {i < reconstruction.attackChain.length - 1 && <ArrowRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />}
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border bg-card p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">{t('reconstruction.patientZero')}</h2>
        <div className="flex items-center gap-4">
          <div className="text-2xl font-mono font-bold text-primary">{reconstruction.patientZero.entity}</div>
          <div className="text-sm">
            <span className="text-muted-foreground">{t('reconstruction.confidence')}: </span>
            <span className="font-bold">{reconstruction.patientZero.confidence}%</span>
          </div>
        </div>
        <p className="text-xs text-muted-foreground mt-1">{reconstruction.patientZero.evidence}</p>
      </div>

      <div className="rounded-lg border bg-card p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">{t('reconstruction.attackPath')}</h2>
        <div className="flex items-center gap-2 flex-wrap font-mono text-sm">
          {reconstruction.attackPath.map((node, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="px-2 py-1 rounded bg-muted">{node}</span>
              {i < reconstruction.attackPath.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground" />}
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border bg-card p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">{t('reconstruction.impacts')}</h2>
        <div className="space-y-2">
          {reconstruction.estimatedImpacts.map((impact, i) => (
            <div key={i} className="flex items-start gap-3 text-sm">
              <SeverityBadge severity={impact.severity} />
              <div>
                <span className="font-semibold">{impact.area}</span>
                <p className="text-xs text-muted-foreground">{impact.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border bg-card p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">{t('reconstruction.story')}</h2>
        <div className="prose prose-sm prose-invert max-w-none text-sm whitespace-pre-wrap">{reconstruction.story}</div>
      </div>
    </div>
  );
}
