import {
  LayoutDashboard, Microscope, AlertTriangle, Search,
  Clock, Swords, GitBranch, ShieldCheck, Download, Gauge,
} from 'lucide-react';
import { NavLink } from '@/components/NavLink';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar';
import { useLanguage } from '@/context/LanguageContext';

export function AppSidebar() {
  const { state } = useSidebar();
  const { t } = useLanguage();
  const collapsed = state === 'collapsed';

  const items = [
    { title: t('sidebar.overview'), url: '/', icon: LayoutDashboard },
    { title: t('sidebar.analysis'), url: '/analysis', icon: Microscope },
    { title: t('sidebar.alerts'), url: '/alerts', icon: AlertTriangle },
    { title: t('sidebar.investigations'), url: '/investigations', icon: Search },
    { title: t('sidebar.timeline'), url: '/timeline', icon: Clock },
    { title: t('sidebar.reconstruction'), url: '/reconstruction', icon: Swords },
    { title: t('sidebar.graph'), url: '/graph', icon: GitBranch },
    { title: t('sidebar.benchmark'), url: '/benchmark', icon: Gauge },
    { title: t('sidebar.hardening'), url: '/hardening', icon: ShieldCheck },
    { title: t('sidebar.exports'), url: '/exports', icon: Download },
  ];

  return (
    <Sidebar collapsible="icon">
      <SidebarContent>
        <div className="p-4 border-b border-sidebar-border">
          {collapsed ? (
            <span className="text-lg font-bold text-primary font-mono">A</span>
          ) : (
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center shadow-sm shadow-primary/20">
                <span className="text-primary font-bold font-mono text-sm">AD</span>
              </div>
              <div>
                <h1 className="text-lg font-bold text-primary font-mono glow-text">ADFT UI</h1>
                <p className="text-[10px] text-sidebar-foreground/60 leading-tight">{t('sidebar.integratedGui')}<br />v1.0</p>
              </div>
            </div>
          )}
        </div>

        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {items.map((item) => (
                <SidebarMenuItem key={item.url}>
                  <SidebarMenuButton asChild>
                    <NavLink to={item.url} end={item.url === '/'} className="hover:bg-sidebar-accent/50" activeClassName="bg-sidebar-accent text-primary font-medium">
                      <item.icon className="mr-2 h-4 w-4" />
                      {!collapsed && <span>{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
