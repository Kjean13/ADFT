import { Severity } from '@/engine/types';
import { cn } from '@/lib/utils';
import { severityColor, severityBg } from '@/lib/forensic-utils';
import { severityLabel, useLanguage } from '@/context/LanguageContext';

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { language } = useLanguage();

  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold uppercase',
      severityColor(severity),
      severityBg(severity),
    )}>
      {severityLabel(language, severity)}
    </span>
  );
}
