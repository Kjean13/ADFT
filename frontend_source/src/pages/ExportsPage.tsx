import { useADFT } from '@/context/ADFTContext';
import { Button } from '@/components/ui/button';
import { Download, Eye, FileCode2 } from 'lucide-react';
import { artifactUrl } from '@/lib/api';
import { useLanguage } from '@/context/LanguageContext';

function humanSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

export default function ExportsPage() {
  const { artifacts, run } = useADFT();
  const { t } = useLanguage();
  const hasData = run.status === 'complete' || artifacts.length > 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">{t('exports.title')}</h1>
        <p className="text-muted-foreground text-sm">{t('exports.subtitle')}</p>
      </div>

      {!hasData ? (
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <Download className="h-16 w-16 mb-4 opacity-30" />
          <p>{t('exports.empty')}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {artifacts.map((artifact) => (
            <div key={artifact.name} className="rounded-lg border bg-card p-4 space-y-3">
              <div className="flex items-start gap-3">
                <FileCode2 className="h-5 w-5 text-primary mt-0.5" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium truncate">{artifact.label}</p>
                  <p className="text-xs text-muted-foreground font-mono break-all">{artifact.name}</p>
                </div>
              </div>
              <div className="text-xs text-muted-foreground flex items-center justify-between">
                <span>{humanSize(artifact.size_bytes)}</span>
                <span>{new Date(artifact.created_at * 1000).toLocaleString()}</span>
              </div>
              <div className="flex gap-2">
                {artifact.preview_url && (
                  <Button variant="outline" size="sm" asChild>
                    <a href={artifact.preview_url} target="_blank" rel="noreferrer">
                      <Eye className="h-4 w-4 mr-1" /> {t('exports.preview')}
                    </a>
                  </Button>
                )}
                <Button size="sm" asChild className="ml-auto">
                  <a href={artifactUrl(artifact.name)} target="_blank" rel="noreferrer">
                    <Download className="h-4 w-4 mr-1" /> {t('exports.download')}
                  </a>
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
