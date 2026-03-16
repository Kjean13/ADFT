import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Languages, Shield, Workflow } from 'lucide-react';
import { Toaster as Sonner } from '@/components/ui/sonner';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { SidebarProvider, SidebarTrigger } from '@/components/ui/sidebar';
import { AppSidebar } from '@/components/AppSidebar';
import { ADFTProvider } from '@/context/ADFTContext';
import { LanguageProvider, useLanguage } from '@/context/LanguageContext';
import OverviewPage from './pages/OverviewPage';
import AnalysisPage from './pages/AnalysisPage';
import AlertsPage from './pages/AlertsPage';
import InvestigationsPage from './pages/InvestigationsPage';
import TimelinePage from './pages/TimelinePage';
import ReconstructionPage from './pages/ReconstructionPage';
import GraphPage from './pages/GraphPage';
import BenchmarkPage from './pages/BenchmarkPage';
import HardeningPage from './pages/HardeningPage';
import ExportsPage from './pages/ExportsPage';
import NotFound from './pages/NotFound';

const queryClient = new QueryClient();

function Shell() {
  const { language, setLanguage, t } = useLanguage();

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <header className="h-12 flex items-center justify-between border-b border-border px-3 flex-shrink-0 bg-background/95 backdrop-blur">
            <div className="flex items-center gap-2 min-w-0">
              <SidebarTrigger />
              <div className="flex items-center gap-2 min-w-0">
                <div className="h-7 w-7 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
                  <Shield className="h-4 w-4 text-primary" />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold tracking-wide">ADFT UI</div>
                  <div className="text-[10px] text-muted-foreground font-mono">{t('app.subtitle')}</div>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="hidden md:flex items-center gap-2 text-[11px] text-muted-foreground font-mono">
                <Workflow className="h-3.5 w-3.5" />
                <span>{t('app.version')}</span>
              </div>
              <div className="flex items-center gap-1 rounded-md border bg-muted/50 px-1 py-1">
                <Languages className="h-3.5 w-3.5 text-muted-foreground mx-1" />
                <button
                  type="button"
                  onClick={() => setLanguage('fr')}
                  className={`rounded px-2 py-1 text-[11px] font-mono ${language === 'fr' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  {t('lang.fr')}
                </button>
                <button
                  type="button"
                  onClick={() => setLanguage('en')}
                  className={`rounded px-2 py-1 text-[11px] font-mono ${language === 'en' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'}`}
                >
                  {t('lang.en')}
                </button>
              </div>
            </div>
          </header>
          <main className="flex-1 p-6 overflow-auto">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/analysis" element={<AnalysisPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/investigations" element={<InvestigationsPage />} />
              <Route path="/timeline" element={<TimelinePage />} />
              <Route path="/reconstruction" element={<ReconstructionPage />} />
              <Route path="/graph" element={<GraphPage />} />
              <Route path="/benchmark" element={<BenchmarkPage />} />
              <Route path="/hardening" element={<HardeningPage />} />
              <Route path="/exports" element={<ExportsPage />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <LanguageProvider>
          <ADFTProvider>
            <Shell />
          </ADFTProvider>
        </LanguageProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
