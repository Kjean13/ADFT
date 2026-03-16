import { cn } from '@/lib/utils';
import { ReactNode } from 'react';

interface KPICardProps {
  label: string;
  value: string | number;
  icon?: ReactNode;
  className?: string;
  accent?: boolean;
}

export function KPICard({ label, value, icon, className, accent }: KPICardProps) {
  return (
    <div className={cn(
      "rounded-lg border bg-card p-4 flex flex-col gap-1",
      accent && "glow-border",
      className
    )}>
      <div className="flex items-center gap-2 text-muted-foreground text-xs uppercase tracking-wider">
        {icon}
        {label}
      </div>
      <div className={cn("text-2xl font-bold font-mono", accent && "text-primary glow-text")}>
        {value}
      </div>
    </div>
  );
}
